# Live results W39: Windows install modes (rdp, sqlserver, NLA discovery)

Date: 2026-10-25 (final run). Hub built from `feat/v1.1-windows` head `d5df926b` (code unchanged, no product fixes this run).
Lab: lab-ws22 192.0.2.104 (Server 2022), lab-win11 192.0.2.102 (Windows 11). Hub run on `127.0.0.1:18439` only, fresh data dir, local CA `W39 Test Root CA`,
`KRYPTKEEPER_WINRM_CA_CERT_FILE` = the two self-signed listener certificates. No secrets are recorded here.

## Verdict: PASS for W35-04 rdp (both hosts), W24-48 (hub discovery, NLA), W35-02 sqlserver. W24-50 and W35-03 not run.

Authorised lab changes (the owner, project thread, 2026-10-25T15:01Z): temp local Administrator, self-signed 5986 HTTPS listener, service Basic=true (original `false`).
Also used: RDP enabled temporarily, SQL Server Express install on lab-ws22. All reverted except the SQL install (see Revert).

| Scenario | Result |
|---|---|
| 1. W35-04 rdp, lab-ws22 | PASS: `installed_verified`, independent Mac probe serves the hub leaf; rollback PASS |
| 1. W35-04 rdp, lab-win11 | PASS: same |
| 2. W24-48 hub discovery of 3389 with NLA required | PASS |
| 3. W35-02 sqlserver, lab-ws22 | PASS: `installed_verified`, ScanTDS from the Mac serves the new leaf; rollback PASS |
| 4. W24-50 Windows agent | NOT RUN: no agent installed (agent is discovery-only; see v1 doc) |
| 5. W35-03 Exchange | NOT RUN: no Exchange server in the lab |

## Setup evidence

Credential preflight (`windows_password`, `https://<ip>:5986/wsman`, temp admin): `level=install`, `can_discover` and `can_install` true.
Both listeners carry an IP SAN (`openssl x509 -ext subjectAltName`: `DNS:<fqdn>, DNS:<short>, IP Address:<ip>`). `AllowUnencrypted` stayed `false`.
Setup trap: a cert whose CN is not the listener Hostname is refused by `winrm create` (`certificate CN and hostname do not match`); the CN must equal the FQDN.

## 1. W35-04 rdp

Baseline (both): `fDenyTSConnections=1`, TermService Stopped/Manual, NLA required (`UserAuthenticationRequired=1`), `SSLCertificateSHA1HashType=1` (default self-signed).
Baseline default-cert SHA-1: ws22 22C2594F...6891 (regenerated on TermService start, E823E441... this run), win11 D77BF8B6... (this run 9550FA96...).
RDP enabled temporarily (`fDenyTSConnections=0`, "Remote Desktop" rules, TermService started). Targets: `install_mode=rdp`, `discovery_mode=winrm`, temp-admin credential. A predecessor
leaf (RSA-3072, SAN DNS+IP) was issued from the hub CA, then `POST /renewal/execute`.

| Host | API result | WMI after | Independent check (`go run`-style probe calling `ScanRDP` from the Mac) |
|---|---|---|---|
| lab-ws22 | `install_outcome=installed_verified`, `verified=true`, new_fingerprint 5fcfa0be...0356d25 | hash DDD0F87A... type 3 (custom), NLA still 1 | 3389 serves `CN=lab-ws22.corp.example.test`, issuer `CN=W39 Test Root CA`, sha256 5fcfa0be...0356d25, TLS1.2: equals `new_fingerprint` |
| lab-win11 | `installed_verified`, new_fingerprint c7c14425...c89521 | hash 57503C13... type 3, NLA 1 | 3389 serves `CN=LAB-WIN11.corp.example.test`, issuer W39 Test Root CA, sha256 c7c14425...c89521, TLS1.3 |

Rollback (second renewal with `install.verify_host_port` pointed at `<ip>:5986`, which does not speak RDP): both hosts `install_outcome=verify_failed`,
"no certificate served at the verify address", `verified=false`. The WMI hash stayed at the first installed leaf (DDD0F87A / 57503C13) and the Mac probe still served the first leaf's fingerprint. Audit: three
`certificate.renew_execute` success and three `partial` rows, each with a `key.generate_for_renewal` row.
Finding R1 (cosmetic, not fixed): the rolled-back (never active) leaf stays in `LocalMachine\My` (ws22 52C0A0D6, 4C4D8D29; win11 C8E51ABB). The IIS path was documented as leaving none; harmless, removed in the revert below.

## 2. W24-48 hub discovery, NLA required

`POST /discovery/scans {"scan_type":"targeted","target":"<ip>:3389"}` for both hosts (NLA required on both); both jobs `completed`. `GET /discovery/endpoints` excerpt:

```
hostname 192.0.2.104 port 3389 protocol rdps tech rdp platform windows
  mapped_certs[0]: fingerprint 5fcfa0be...0356d25 common_name lab-ws22.corp.example.test issuer_dn "CN=W39 Test Root CA,O=Kryptkeeper"
                   issuer_class hub trust_class managed chain_trusted true
hostname 192.0.2.102 port 3389 protocol rdps tech rdp platform windows
  mapped_certs[0]: fingerprint c7c14425...c89521 common_name LAB-WIN11.corp.example.test issuer_dn "CN=W39 Test Root CA,O=Kryptkeeper"
                   issuer_class hub trust_class managed chain_trusted true
```

So the captured certificate is the one installed by scenario 1, found by the hub's own scanner against an NLA-required listener.

## 3. W35-02 sqlserver (lab-ws22)

Download: `https://go.microsoft.com/fwlink/p/?linkid=2216019` gave the Express web installer (4.6 MB), `Get-AuthenticodeSignature` Valid, signer `CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond`.
The bootstrapper downloaded the media `SQLEXPR_x64_ENU.exe` (749 MB, sha256 74AA90C1...5297), also Valid with the Microsoft signer, checked before it was run.
Silent install from a SYSTEM scheduled task (`/Q /ACTION=Install /FEATURES=SQLEngine /INSTANCENAME=MSSQLSERVER /TCPENABLED=1 /SQLSYSADMINACCOUNTS=BUILTIN\Administrators /UPDATEENABLED=False`,
Windows authentication only, no SQL login or `sa`): Summary `Final result: Passed`, 4 minutes. **Note: that link now delivers SQL Server 2025 Express (17.0.1000.7, instance id `MSSQL17.MSSQLSERVER`), not 2022**; the brief said 2022.
The installer's `/Action=Install` form exited silently with no install; the Download then media-install path worked. A Windows Firewall inbound rule for TCP 1433 was added (`SQL Server 1433 W39`).

Before: `Certificate` registry value empty; ScanTDS served `CN=SSL_Self_Signed_Fallback` (sha256 179af9c3...07d3).
Hub: credential `windows_password` (blank `sql_instance`), target `install_mode=sqlserver`, `verify_host_port=192.0.2.104:1433`, issue + `POST /renewal/execute`:
`installed_verified`, `verified=true`, new_fingerprint 10dee811...800914. Host after: `...\MSSQL17.MSSQLSERVER\MSSQLServer\SuperSocketNetLib\Certificate` = `27448bbc4f5f2adabad2ccd99052efbabdab7ccf` (lowercase thumbprint), MSSQLSERVER service Running.
Independent `ScanTDS` from the Mac (PRELOGIN-framed TLS): `CN=lab-ws22.corp.example.test`, issuer `CN=W39 Test Root CA`, sha256 10dee811...800914, TLS1.2: equals `new_fingerprint`.
Rollback: second renewal with `verify_host_port=<ip>:3389`: `verify_failed`; registry value stayed 27448bbc..., service Running, ScanTDS still served 10dee811... (same R1: the unused leaf stays in `My`).

## Revert (verified on both hosts by PowerShell, after the hub was stopped by PID)

| Item | Evidence (both hosts) |
|---|---|
| Temp admin `lab-w39adm` | `user present: False`; Administrators = Domain Admins, local Administrator, labadmin (as before) |
| HTTPS listener 5986 | `winrm enumerate` shows only HTTP 5985; `port5986 listening: False`; Mac connect to 5986 times out |
| Basic | `Basic=false` (original value false), `AllowUnencrypted=false` |
| Firewall rule `WinRM HTTPS W39` | `present: False` |
| Listener self-signed cert and `C:\w39-listener.cer` | removed; `LocalMachine\My` back to the GPO-autoenrolled cert only |
| RDP | `fDenyTSConnections=1`, TermService Stopped/Manual, 0 enabled "Remote Desktop" rules, custom `SSLCertificateSHA1Hash` value removed, 3389 closed from the Mac, `Remote Desktop` store empty. The WMI hash property reads the service's regenerated default cert with type 1 (baseline type 1), as in the previous run |
| W39 hub-issued certs | removed from `LocalMachine\My` on both, except ws22 `27448BBC...` which SQL Server uses |
| Local artefacts | temp admin password file and state deleted; hub data dir deleted; probe program deleted (never committed) |

**Left in place on lab-ws22 (as the brief allowed): SQL Server 2025 Express, default instance, Running, TCP 1433 open (firewall rule `SQL Server 1433 W39`), serving the hub-issued leaf `CN=lab-ws22.corp.example.test` from `W39 Test Root CA`.** The temp hub's CA is gone, so that leaf is no longer chained to anything the lab trusts; reinstall or remove the `Certificate` registry value and restart `MSSQLSERVER` to return to the fallback cert. Nothing was changed on lab-win11 beyond the revert state above.

## W39-01 domain-account install (follow-up run)

Date: 2026-10-25. Hub built from `feat/v1.1-windows` head `da51d63e` (W39-01 sealed-NTLM install plus the R1 rollback cleanup), run on `127.0.0.1:18439` only, fresh data dir, local CA `W39 Test Root CA`.
No temp admin, no HTTPS listener, no Basic auth were created; the hub root was never imported into the host. Authorised change: RDP enabled temporarily on lab-ws22 (restored below). No secrets recorded.
Credential: `windows_password`, `base_url=http://192.0.2.104:5985/wsman`, account `CORP\Administrator` (domain administrator), target `install_mode=rdp`, `discovery_mode=winrm`.

Verdict: **PASS** for W39-01 (domain-account install over sealed NTLM) and R1 (rolled-back leaf removed from `LocalMachine\My`).

| Check | Evidence |
|---|---|
| Listener/auth unchanged (`winrm get winrm/config/service`) | before and after identical: `AllowUnencrypted=false`, `Basic=false`, Kerberos/Negotiate true, Certificate/CredSSP false; listeners: HTTP 5985 only; `5986 listening: False` |
| Preflight | `POST /credentials/{id}/preflight`: `level=install`, `can_discover=true`, `can_install=true` (detail: elevated token) |
| Renewal over sealed NTLM | `POST /renewal/execute`: `install_outcome=installed_verified`, `verified=true`, new_fingerprint f1bb8c22...f0670; WMI hash type 3 (custom), NLA still 1 |
| Independent Mac probe (`ScanRDP`) | 3389 serves `CN=lab-ws22.corp.example.test`, issuer `CN=W39 Test Root CA`, sha256 f1bb8c22...f0670, equals `new_fingerprint` |
| Forced verify failure (`install.verify_host_port=192.0.2.104:5986`, closed) | `install_outcome=verify_failed`, "no certificate served at the verify address", `verified=false` (new_fingerprint 40ae8953...528c, never installed) |
| Rollback | `LocalMachine\My` thumbprint list identical before and after the failed run (the new leaf was imported then removed; R1 fixed); WMI hash still 1B4930...; Mac probe still serves f1bb8c22...f0670 |
| Audit | `certificate.renew_execute` success, then `certificate.renew_execute` partial `install_outcome=verify_failed`, each with `key.generate_for_renewal` and `key.zeroize` (`installed=true` / `installed=false`) |

### Revert (verified by PowerShell and a Mac probe, after the hub was stopped by PID)

`fDenyTSConnections=1`, TermService Stopped/Manual, 0 enabled "Remote Desktop" firewall rules, custom `SSLCertificateSHA1Hash` value removed (WMI hash type 1 again, default self-signed cert, regenerated as in earlier runs), hub leaf `1B4930...` removed from `My`, 3389 closed from the Mac, WinRM service config unchanged. Hub data dir and scratch deleted.

**Collateral (needs follow-up): the cleanup removed every `LocalMachine\My` certificate issued by `W39 Test Root CA`, which included `27448BBC...` (the leaf left for SQL Server by the previous run). SQL Server's `Certificate` registry value on lab-ws22 therefore points to a missing thumbprint.** The running service keeps the cert loaded, but a restart of `MSSQLSERVER` would fail until the value is cleared (`...\MSSQL17.MSSQLSERVER\MSSQLServer\SuperSocketNetLib\Certificate` set to empty, then restart). That change was not made in this run (outside the authorised scope; the tool permission was denied).

### SQL Server certificate repair (2026-10-25 15:39Z, the owner: "fix sql")

The follow-up run's cleanup had removed the W39 test leaf SQL Server was configured to use. Repaired over WinRM as CORP\Administrator: `MSSQL17.MSSQLSERVER\MSSQLServer\SuperSocketNetLib\Certificate` changed from `27448bbc…7ccf` to empty, MSSQLSERVER restarted, status `Running`. SQL Server 2025 Express on lab-ws22 now uses its own self-generated certificate.
