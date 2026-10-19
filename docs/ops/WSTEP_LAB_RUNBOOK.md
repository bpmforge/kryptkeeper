# WSTEP / XCEP lab runbook (W26-14)

Recipe for a Kerberos + GPO autoenrollment lab from nothing. Design and audit
semantics live in [WSTEP_AUTOENROLLMENT.md](WSTEP_AUTOENROLLMENT.md); this page
does not restate them. When something fails, see [WSTEP_FAILURES.md](WSTEP_FAILURES.md).

Verification status: every step below was proven on the `corp.example.test` lab with a
Windows Server 2025 DC and a Windows 11 client (W18-08, 2026-10-07/08) unless
marked `(unverified)`. The Windows 10 / Server 2019 / Server 2022 matrix run
(W26-13, `docs/release/LIVE_RESULTS_FG2_WSTEP_MATRIX_v0.14.md`) is `PENDING-RUN`, so
nothing here is yet cross-checked against it, and no second operator has followed it
(see the footer). The fixture domain is `corp.example.test`; use no real passwords here.

## 1. Lab topology

One domain controller (`lab-dc01`, `corp.example.test`), the hub (`lab-hub.corp.example.test`), and one
domain-joined client per target OS (Windows 10, Server 2019, Server 2022; Windows 11
is the proven reference). Clients must reach the hub by DNS name.

Expected: from each client, `Resolve-DnsName lab-hub.corp.example.test` returns the hub's IP.

## 2. Active Directory and DNS

1. Create the domain and join the clients.
2. On the DC, add a DNS A record `lab-hub.corp.example.test` for the hub.
3. Put the target machines in an OU (for example `OU=KKLab`) so the GPO can be linked
   there instead of at the domain root.

Expected: `nslookup lab-hub.corp.example.test` on a client resolves; the clients show as domain
members.

Windows only uses Kerberos when it addresses the hub by DNS name. Against an IP it
falls back to NTLM, which the hub rejects with a 401.

## 3. Service account, SPN and keytab

1. Create a dedicated service account (for example `svc-kkhub`).
2. Register the SPN: `setspn -S HTTP/lab-hub.corp.example.test svc-kkhub`.
3. Generate the keytab with `ktpass` using `/crypto AES256-SHA1` (the other flags
   `(unverified)`: `/princ HTTP/lab-hub.corp.example.test@CORP.EXAMPLE.TEST /mapuser svc-kkhub /ptype KRB5_NT_PRINCIPAL /pass * /out lab-hub.keytab`).
   Never print `ktpass`'s key line: it echoes the derived key in hex.
4. Move the keytab to the hub over a sealed channel only, delete it from the DC, and set
   mode 0600: `chmod 600 /etc/kryptkeeper/wstep.keytab`.
5. The SPN string must match the keytab entry exactly. The match is case-sensitive.

Expected: `setspn -L svc-kkhub` lists `HTTP/lab-hub.corp.example.test`; on the hub
`ls -l` shows `-rw-------` on the keytab.

## 4. Hub environment and TLS

Set on the hub (constants `EnvKeytabFile`, `EnvSPN` in `internal/wstep/kerberos.go`):

```bash
export KRYPTKEEPER_WSTEP_KEYTAB_FILE=/etc/kryptkeeper/wstep.keytab
export KRYPTKEEPER_WSTEP_SPN=HTTP/lab-hub.corp.example.test
export KRYPTKEEPER_TLS_SANS=lab-hub.corp.example.test
```

Both WSTEP variables must be set. The hub's TLS certificate must carry the DNS name
(`KRYPTKEEPER_TLS_SANS`), and every client must trust the hub CA in
`LocalMachine\Root`. Optional: `KRYPTKEEPER_WSTEP_URL`,
`KRYPTKEEPER_XCEP_RENEWAL_PERIOD`, `KRYPTKEEPER_XCEP_POLICY_ID`,
`KRYPTKEEPER_REVOCATION_HTTP_ADDR` / `KRYPTKEEPER_REVOCATION_BASE_URL` (plain-HTTP CRL/OCSP,
see the autoenrollment page "Revocation pointers").

Expected: the startup log does not report an error naming the keytab or SPN, and
`GET /api/v1/integrations/microsoft` reports WSTEP/XCEP as enabled. An unauthenticated
`curl -ik https://lab-hub.corp.example.test:8443/xcep` returns `401` with `WWW-Authenticate: Negotiate`.

## 5. Templates

1. Create a machine template with `active=true`, `auto_enroll=true`, an OID under
   `1.3.6.1.4.1.311.21.8` and `extended_key_usage=[clientAuth]`
   (`POST /api/v1/templates`; lab values: `name=KKMachine`,
   `oid=1.3.6.1.4.1.311.21.8.4150237.1.1`). `enrollee_type` defaults to machine.
2. For user autoenrollment create a second template with `enrollee_type=user`
   (`name=KKUser`, `oid=1.3.6.1.4.1.311.21.8.4150237.3.1`).
3. Optionally publish the templates to AD with `POST /api/v1/adsync/templates` (approver
   capability, writes to the AD Configuration partition; per-template errors come back in `errors`).

Expected: XCEP offers a machine only the machine template, and a user only the user template.

## 6. GPO

Run the "Domain controller (GPO)" block from
[WSTEP_AUTOENROLLMENT.md](WSTEP_AUTOENROLLMENT.md) verbatim: policy server URL
`https://lab-hub.corp.example.test:8443/xcep`, `AuthFlags=2` (Kerberos), `AEPolicy=7`, then
`New-GPLink` to the target OU. Keep the filter that applies the GPO to `Domain Computers`
only, so Domain Controllers do not autoenroll.

Expected: `Get-GPO 'KK Certificate Autoenrollment'` exists, and `gpresult /r /scope computer`
on a client lists it under applied GPOs.

## 7. First pulse

On the client, elevated:

```powershell
certutil -f -PolicyServer * -PolicyCache delete
gpupdate /force /target:computer
certutil -pulse
```

Expected: within about 20 seconds `Get-ChildItem Cert:\LocalMachine\My` shows a certificate
issued by the hub CA with subject `CN=<host>.corp.example.test` and the same DNS SAN; the
hub audit log has a `wstep.enroll` `success` row (query in WSTEP_FAILURES.md). Windows caches
policy for 8 hours, hence the first line. For evidence capture use `tests/live/wstep/matrix/`.

## 8. Teardown

1. Unlink and remove the GPO: `Remove-GPLink`, `Remove-GPO`.
2. Delete the keytab from the hub and the DC; `setspn -D HTTP/lab-hub.corp.example.test svc-kkhub`; remove the service account.
3. Revoke or delete the test certificates; remove the test templates.
4. On clients: `certutil -f -PolicyServer * -PolicyCache delete`.

Expected: `certutil -pulse` on a client no longer enrolls; the hub log shows no further `wstep.enroll` rows.

## Verification record (second-operator check)

| Operator | Date | Target OS | Steps that needed deviation |
|---|---|---|---|
| PENDING | PENDING | PENDING | PENDING (each deviation fixes this runbook before W26-14 closes) |
