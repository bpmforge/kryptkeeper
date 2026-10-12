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
| credential | `windows_password`, a **local** account, no `DOMAIN\` prefix (Basic auth rejects domain accounts) |
| `discovery_mode` | `winrm` |
| `install_mode` | `iis` |

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
