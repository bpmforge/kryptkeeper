# Enabling WinRM for agentless Windows targets

How to get a Windows host into a state Kryptkeeper can discover and install
to, **without disabling any of its hardening defaults**.

Companion to `docs/ops/WINDOWS_ACCESS_MATRIX.md`, which explains *why* this is
the supported path. Board: W18-06, W18-10, W18-11.

> Examples below use `192.0.2.10` (RFC 5737 TEST-NET-1, a documentation
> address) and a placeholder `<local-user>` in place of the actual lab host
> and account used when this runbook was written.

## The rule this runbook exists to keep

`AllowUnencrypted` stays **`false`**. It is a *message-layer* requirement,
independent of authentication: over plain HTTP, WinRM rejects an unencrypted
SOAP body even after auth succeeds. **HTTPS satisfies it** — TLS *is* the
encryption — which is why an HTTPS listener, not an extra auth mechanism, is
what makes agentless Windows work.

Anyone who tells you to run `winrm set winrm/config/service
@{AllowUnencrypted="true"}` is telling you to put your password on the wire in
base64 cleartext. That is a lab shortcut, never a documented path.

## Step 1 — the listener certificate (on the Windows host, elevated)

> **The trap.** Go matches an IP address **only against IP SANs**, never
> against a DNS SAN or the CN. `New-SelfSignedCertificate -DnsName
> "192.0.2.10"` puts that string in a *DNS* SAN and produces a certificate
> Kryptkeeper will reject with *"cannot validate certificate for
> 192.0.2.10 because it doesn't contain any IP SANs"*. Verified against
> `crypto/x509` on 2026-08-27. Use `-TextExtension`.

```powershell
$ip   = '192.0.2.10'
$fqdn = [System.Net.Dns]::GetHostByName($env:COMPUTERNAME).HostName

$cert = New-SelfSignedCertificate `
  -Subject "CN=$fqdn" `
  -CertStoreLocation Cert:\LocalMachine\My `
  -KeyExportPolicy NonExportable `
  -KeyUsage DigitalSignature,KeyEncipherment `
  -TextExtension @(
    "2.5.29.37={text}1.3.6.1.5.5.7.3.1",                  # EKU: Server Authentication
    "2.5.29.17={text}DNS=$fqdn&DNS=$env:COMPUTERNAME&IPAddress=$ip"
  ) `
  -NotAfter (Get-Date).AddYears(1)

$cert.Thumbprint
```

Both an IP SAN and DNS SANs are set, so the target works whether Kryptkeeper
addresses it by IP or by name. Server Authentication EKU is required —
Schannel will not use the certificate without it.

## Step 2 — the HTTPS listener and firewall (elevated)

```powershell
winrm create winrm/config/Listener?Address=*+Transport=HTTPS `
  "@{Hostname=`"$fqdn`"; CertificateThumbprint=`"$($cert.Thumbprint)`"}"

New-NetFirewallRule -DisplayName "WinRM HTTPS (Kryptkeeper)" `
  -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow

winrm enumerate winrm/config/Listener     # confirm an HTTPS listener exists
```

## Step 3 — auth (elevated)

Kryptkeeper authenticates with HTTP Basic **over TLS**. Enable it on the
**service**, and leave everything else alone:

```powershell
winrm set winrm/config/service/auth '@{Basic="true"}'
winrm get winrm/config/service            # Basic=true, AllowUnencrypted STILL false
```

`AllowBasic` is the **client**-side setting (`winrm/config/client/auth`) and
has no effect on a Go client. Do not change it.

## Step 3b — a non-administrator discovery account (elevated)

Discovery needs only reads, so the credential Kryptkeeper stores for
`discovery_mode=winrm` should be a **standard** local user. Two things stand
between such a user and a WinRM shell, and both were captured live on
2026-09-10 against Windows 11 22621:

```powershell
Add-LocalGroupMember -Group "Remote Management Users" -Member <user>
winrm get winrm/config/service | findstr /i RootSDDL
```

If the `RootSDDL` line does **not** contain `(A;;GA;;;RM)`, the group grants
nothing on this host — Windows **client** editions ship a descriptor that
admits only Administrators. Add the group:

```powershell
Set-Item WSMan:\localhost\Service\RootSDDL -Value "O:NSG:BAD:P(A;;GA;;;BA)(A;;GR;;;IU)(A;;GA;;;RM)S:P(AU;FA;GA;;;WD)(AU;SA;GXGW;;;WD)"
```

What the hub sees for each way a credential can be wrong — the first row is
the one to know about, because the wire cannot tell its two causes apart:

| Host state | Hub-side error |
|---|---|
| Wrong password **or** valid password for an account outside the RootSDDL | bare `HTTP 401`, identical in both cases |
| Admitted by the RootSDDL, but not permitted to create a shell | `HTTP 500` with WSManFault `Code="5"` on Create |
| Shell works, account is not a local Administrator | install fails at the ProgramData staging write with `HRESULT 0x80070005`; the error says the credential authenticated and names the operation (W18-10) |

## Step 4 — teach the hub to trust the listener (on the hub)

Export the public certificate — **public only, no key leaves the host**:

```powershell
Export-Certificate -Cert $cert -FilePath C:\winrm-listener.cer -Type CERT
certutil -encode C:\winrm-listener.cer C:\winrm-listener.pem
```

Copy the PEM to the hub and point Kryptkeeper at it:

```bash
export KRYPTKEEPER_WINRM_CA_CERT_FILE=/etc/kryptkeeper/winrm-listener.pem
# or inline:
export KRYPTKEEPER_WINRM_CA_CERT="$(cat winrm-listener.pem)"
```

A self-signed listener certificate is its own root, so the exported
certificate *is* the bundle. There is deliberately **no skip-verify option**:
a product whose job is distributing trust does not switch verification off to
deliver a certificate. A bundle that parses to nothing is a startup error, not
a silent fall back to the system roots.

## Step 5 — verify from the hub before involving Kryptkeeper

```bash
openssl s_client -connect 192.0.2.10:5986 -showcerts </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -ext subjectAltName
```

The `subjectAltName` must list `IP Address:192.0.2.10`. If it shows only
`DNS:`, go back to step 1 — that is the trap above, and it fails at install
time rather than here.

## Step 6 — the target

| Field | Value |
|---|---|
| `base_url` | `https://192.0.2.10:5986/wsman` — full URL, port and `/wsman` path included; nothing normalizes it |
| credential | `windows_password`: over `https://...:5986` a **local** account, no `DOMAIN\` prefix (Basic auth rejects domain accounts); over `http://...:5985/wsman` a domain or local account (see "Domain-account installs over sealed NTLM") |
| `discovery_mode` | `winrm` |
| `install_mode` | `iis`, `sqlserver` or `rdp` (see "Rights each install mode needs") |

**Privilege**: discovery needs only a standard user — reads succeed
unprivileged. **Install needs a local Administrator**: the ProgramData staging
write, the LocalMachine store import and `netsh http add sslcert` all require
elevation. Kryptkeeper reports that distinctly from a bad password (W18-10),
and the credential's **Test credential** button in Target Setup says up front
whether it can only discover or also install (W18-11). Observed 2026-09-10 on
Windows 11 22621: a local Administrator over Basic-on-HTTPS received a
**High-integrity** token (no UAC remote filtering), and a full IIS install —
import, rebind 443, `iisreset`, verify the served leaf — completed and was
confirmed by an independent TLS dial from the hub. The PFX is built on the
hub; the private key never lands on the host unencrypted.

## Rights each install mode needs

Every Windows install mode is the same account on the same channel: a **local
Administrator** over WinRM. They differ in what they touch, which is what to
check when an install fails with `HRESULT 0x80070005` (the error names the
operation, W18-10).

| Mode | Touches | Needs |
|---|---|---|
| `iis` | the ProgramData staging directory, `Cert:\LocalMachine\My`, the HTTP.sys binding (`netsh http add sslcert`), `iisreset` | local Administrator |
| `sqlserver` (W35-02) | the staging directory, `Cert:\LocalMachine\My`, the ACL of the certificate's private-key file under `ProgramData\Microsoft\Crypto`, `HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\<instance id>\MSSQLServer\SuperSocketNetLib\Certificate`, a restart of the instance service | local Administrator. The account does **not** need to be a SQL login or `sysadmin`: nothing connects to SQL Server except the verify dial. |
| `rdp` (W35-04) | the staging directory, `Cert:\LocalMachine\My`, the ACL of the certificate's private-key file, the `SSLCertificateSHA1Hash` property of `Win32_TSGeneralSetting` (namespace `root\cimv2\TerminalServices`, terminal `RDP-Tcp`) | local Administrator |

**SQL Server details.** The credential carries `sql_instance` (blank means
`MSSQLSERVER`) and `sql_port` (blank means 1433; set it for a named instance on
a fixed port, or set the target's `verify_host_port`). Kryptkeeper reads the
instance's service logon account from `Win32_Service`, grants it **read** on the
imported certificate's private key (Microsoft: the service account "must have
read permissions on the certificate"; without it the restart fails), writes the
thumbprint (lowercase, no spaces) to the `Certificate` registry value for
SQL Server 2019 and 2022 alike, restarts the instance service and any running
dependent service such as SQL Server Agent, then verifies with a TLS handshake
carried inside TDS PRELOGIN (a plain TLS dial to 1433 never reaches the
certificate). **The restart drops every connection to that instance**, so
schedule it like any other maintenance. On a verify failure the previous
`Certificate` value is restored and the service restarted again; if there was
none, the value is removed. A failover-cluster instance needs the same
certificate on every node and is not handled by this mode. Source:
[Encrypt Connections by Importing a Certificate](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-sql-server-encryption).

**RDP details.** Kryptkeeper grants **NETWORK SERVICE** (the listener's account)
read on the imported certificate's private key, sets `SSLCertificateSHA1Hash`
(Microsoft: the SHA-1 hash, in hexadecimal, of the certificate the server uses)
and verifies with an X.224 negotiation followed by the TLS handshake on 3389.
The Remote Desktop service is **not** restarted, so existing sessions are not
dropped; if a host only picks the new certificate up after a restart, the
verify fails and the previous setting is restored rather than the service being
bounced. When `SSLCertificateSHA1HashType` reports the certificate as enforced
by **group policy**, the install refuses before changing anything: change the
policy's certificate template instead. With no previous custom hash, rollback
removes the value so the listener returns to its default certificate. Source:
[Win32_TSGeneralSetting](https://learn.microsoft.com/en-us/windows/win32/termserv/win32-tsgeneralsetting).

## Step 6b — Microsoft Exchange (`install_mode` = `exchange`, W35-03)

Same WinRM channel as IIS, different last step: the renewed certificate is
imported into `LocalMachine\My` exactly as for IIS, then enabled with
`Enable-ExchangeCertificate -Thumbprint <tp> -Services <list> -Force` in an
Exchange Management Shell context. The cmdlets are loaded on the Exchange
server itself with `Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn`
(a remote session to `http://<server>/PowerShell/` would need the account's
credential again inside the script, and Microsoft documents that
`Get-ExchangeCertificate` is not fully supported over remote PowerShell).
References: learn.microsoft.com/powershell/module/exchangepowershell/enable-exchangecertificate
and /powershell/exchange/connect-to-exchange-servers-using-remote-powershell.

| Field | Value |
|---|---|
| credential | `windows_password` for an account that is **both** a local Administrator on the Exchange server (store write) **and** a member of the **Organization Management** or **Server Management** role group (the certificate cmdlets). A member of neither fails with a message naming which is missing. |
| credential JSON | the `base_url`, `username`, `password` of Step 6, plus optional `"services": ["IIS","SMTP"]` (allowed: `IIS`, `SMTP`, `IMAP`, `POP`; default `IIS,SMTP`) and `"smtp_ports": [25, 587]` (default 25 and 587) |
| `verify_host_port` | the OWA HTTPS endpoint; default `<host>:443` |
| `install_mode` | `exchange` |

After enabling, Kryptkeeper runs `iisreset /noforce` when IIS is among the
services, then proves the new leaf is served: a TLS handshake to OWA, and an
SMTP `STARTTLS` handshake on each configured port (a port that does not answer
is skipped, one that answers with a different leaf fails the install, and at
least one must answer). On any failure the previously enabled certificate is
re-enabled for each service. The old certificate is never deleted, and
`-DoNotRequireSsl` is passed so a renewal does not change the default web
site's SSL settings. Only the leaf is imported, as with IIS; an Exchange host
needs its intermediates already in the store.

**Not yet proven on a licensed Exchange host** (a live run must show):
the snap-in loads in a WinRM-launched `powershell.exe` and RBAC resolves the
WinRM account; the credential works over the auth scheme in use (Exchange
accounts are domain accounts, while Basic auth in Step 6 rejects them, so this
needs the NTLM or Negotiate path); `Get-ExchangeCertificate` reports the
certificate currently enabled per service so the rollback target is right (the
IIS flag can sit on several certificates, the longest-lived unexpired one is
chosen); OWA and port 25/587 present the new leaf with no further service
restart (if the transport services cache the old certificate, a restart step
must be added); rollback restores the old leaf on both.

## Domain-account installs over sealed NTLM (W39-01)

Every install mode (`iis`, `sqlserver`, `rdp`, `exchange`) drives the host
through the same `WSManShell` discovery uses, and that shell picks its
transport from the credential's `base_url` scheme alone: `https://...:5986`
is Basic over TLS (local account only), `http://host:5985/wsman` is NTLM with
message sealing and accepts `DOMAIN\user`. There is no separate `auth` field;
one rule serves discovery and installs. So a **domain account in the local
Administrators group** can install with no Basic auth and no HTTPS listener.

What the host needs: the default WinRM listener on 5985 (`winrm quickconfig`
or `Enable-PSRemoting`), `service/auth` `Negotiate=true` (the default),
`AllowUnencrypted` left `false`, and the account in the target's local
**Administrators** group (a domain admin is, via Domain Admins). The sealed
transport refuses, with an error saying so, when the listener offers no
Negotiate/NTLM or answers unsealed; it never falls back to Basic or a plain
body over http. A UAC-filtered token still blocks installs: the preflight
reports `discover` instead of `install` for such an account.

## Fallback: plain HTTP (5985) with NTLM message sealing (W18-09)

Only for hosts that cannot present an HTTPS listener. Give the credential an
`http://host:5985/wsman` URL; the client then authenticates with NTLMv2 and
seals every SOAP body with the session key (RC4, `multipart/encrypted`). The
host keeps its defaults: `AllowUnencrypted=false`, and `service/auth` needs
`Negotiate=true` (the default). Basic is **never** sent over http, and an
unsealed reply is refused.

- Use `DOMAIN\user` or a bare local user (UPN `user@realm` is sent whole).
- Requires a server that grants 128-bit key exchange with a timestamp in its
  challenge (every supported Windows does). A weaker challenge is refused, not
  negotiated down.
- SPNEGO-wrapped challenges (Kerberos-capable `Negotiate` replies) are not
  supported; the client reports it and says to use HTTPS.
- RC4/MD4/MD5 are what the protocol mandates here, not a choice. Prefer HTTPS.
- **Status: verified 2026-10-06 against a real Windows Server 2025 listener**
  (lab DC `lab-dc01`, build 26100, defaults left alone: `AllowUnencrypted=false`)
  as `CORP\Administrator`, by `KK_LIVE_WINRM_HTTP=1 go test
  ./internal/agentdiscovery -run TestLiveWinRMSealedHTTP`. A sealed command ran
  while the listener reported `AllowUnencrypted = false`, discovery over the
  sealed path returned 17 certificates (one legacy root skipped as unparseable,
  as on HTTPS), and a wrong password was a 401. Repeated the same day against a
  domain-joined Windows 11 Enterprise 26100 listener: same three results (18 certs). A 401 after a correct password
  usually means the account is not admitted by the RootSDDL, as with HTTPS.

## The better end state

Once the loop works, reissue the listener certificate **from Kryptkeeper's own
CA** with the same IP SAN, and set the trust bundle to the KK root. The
listener then renews on the same machinery as every other endpoint, and the
product is dogfooding its own issuance. Step 1's self-signed certificate is a
bootstrap, not the destination.

For **domain-joined** hosts, do none of this — use WSTEP autoenrollment
(`internal/wstep`). The machine pulls its own certificate, no inbound port is
opened, and no credential is stored. See the access matrix.

## Repeatable lab recipe and store recall report

Use this after Steps 1-6 to measure how many certificates Kryptkeeper's
WinRM discovery finds against what the host actually holds. Record the result
in `docs/release/DISCOVERY_RATES_v0.12.md` (section "Windows store recall").

1. **Prerequisites.** A Windows 11 host with Steps 1-6 done and reachable from
   the machine running the tests. Export (no real values in this document; take
   the password from your secret store):

   ```bash
   export KK_LIVE_WINRM=1
   export KK_WINRM_URL=https://192.0.2.10:5986/wsman
   export KK_WINRM_USER=<local-user>
   export KK_WINRM_PASS=<from your secret store>
   ```

2. **Ground truth on the host**, per store, in PowerShell:

   ```powershell
   (Get-ChildItem Cert:\LocalMachine\My).Count
   (Get-ChildItem Cert:\LocalMachine\Root).Count
   (Get-ChildItem Cert:\LocalMachine\CA).Count
   ```

3. **Run both live tests** (each is skipped unless `KK_LIVE_WINRM=1`) and note
   the logged certificate count and the job status (`completed`):

   ```bash
   go test ./internal/agentdiscovery -run TestLiveWinRM -v
   go test ./internal/bootstrap -run TestLiveWinRMDiscoveryThroughStores -v
   ```

4. **Inventory count.** `GET /api/v1/discovery/endpoints` for the WinRM
   endpoint and take `len(mapped_certs)`, or use the per-store counts in the
   test log. Fill `ground truth | inventory | delta` for `My`, `Root` and `CA`
   in the recall table of `DISCOVERY_RATES_v0.12.md`.

5. **Pass rule.** Delta 0 for `My`. `Root` and `CA` may be lower only by
   certificates `crypto/x509` rejects, which the scanner logs as warnings;
   state the logged number next to the table. Any other delta is a defect, not
   a rounding difference.

6. **Kerberos.** Kerberos WinRM authentication is deliberately not supported
   until a pilot demands it (UC-C04 decision). Use HTTPS with a local account
   (or the sealed-HTTP fallback above).
