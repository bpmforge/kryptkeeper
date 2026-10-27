# W26-13: WSTEP/XCEP matrix (Windows 10, Server 2019, Server 2022)

Status: **run 2026-10-18 on Windows 11 and Server 2022 (enroll blocked by a hub defect).** Record:
`docs/release/LIVE_RESULTS_FG2_WSTEP_MATRIX_v0.14.md` (verdict `PENDING-RUN`).
Windows 11 was proven 2026-10-08 (see `docs/ops/WSTEP_AUTOENROLLMENT.md`); it is
not re-run here. User-context Kerberos test: `../README.md`.

## Prerequisites

- Hub with `/xcep` and `/wstep` served (`KRYPTKEEPER_WSTEP_KEYTAB_FILE`,
  `KRYPTKEEPER_WSTEP_SPN`), TLS SANs with the hub's DNS name, and
  `KRYPTKEEPER_TLS_REQUEST_CLIENT_CERT` as in the runbook.
- Templates published (`POST /api/v1/adsync/templates`): one machine template
  (default `enrollee_type`) and one `enrollee_type=user` template, both active
  with `auto_enroll=true` and an OID.
- The GPO from "Domain controller (GPO)" in `docs/ops/WSTEP_AUTOENROLLMENT.md`
  linked to the OU of the target machines. Filter it to member machines: a GPO at
  the domain root also hits Domain Controllers.
- Three domain-joined VMs (Windows 10, Server 2019, Server 2022) that trust the hub
  CA in `LocalMachine\Root` and reach the hub by DNS name (by IP, Windows falls back to NTLM).
- On the operator box: `curl`, `python3`, and a hub API token with audit read.

## Per-target run order (same every time)

On the target (elevated PowerShell), from this directory:

1. `.\capture.ps1 start`
2. `.\collect-client.ps1 -HubCaSubject '<substring of the hub CA subject>'`
   (deletes the policy cache, runs `gpupdate /force /target:computer` and `certutil -pulse`,
   waits up to 120 s, dumps the cert, exports the `CertificateServicesClient-Lifecycle-System`
   and `-CertEnroll` event logs)
3. `.\capture.ps1 stop`

On the operator box:

4. `KK_HUB_BASE=... KK_HUB_TOKEN=... ./hub-checks.sh <host>`

Renewal (revision bump):

5. PATCH the machine template on the hub (any PATCH bumps the revision), then on the target
   `certutil -f -PolicyServer * -PolicyCache delete; certutil -pulse`. Expect a new
   certificate, then `./hub-checks.sh <host> --renewed` for a `wstep.renew` row with
   `predecessor=<old serial>`.

Negatives:

6. `.\negative.ps1 -XcepUrl https://<hub>/xcep -HubCaSubject '...'`. Also run
   `certutil -v -PolicyServer <xcep> -Kerberos -Template` in a user session and save it to
   `evidence\<host>\templates-user.txt` for the comparison. Then
   `./hub-checks.sh <host> --skew-denied`.
7. Fill the host's row in the results doc with evidence paths and SHA-256.

## Key-usage check

`ku-check.ps1 -HubCaSubject '<substring>'` pulses autoenrollment and prints the new certificate's key usage, EKU,
key algorithm and `certutil -verify -urlfetch` result. Use it after any change to issued key usage
(`docs/release/LIVE_RESULTS_WINDOWS_KU_WS2025_v1.1.md`).

## Evidence layout

```
evidence/<host>/   (gitignored; archive it)
  client.txt  negative.txt  hub-checks.txt
  events-*.evtx   wstep.etl   wstep.pcapng
  templates-machine.txt   templates-user.txt
  certificates.json   audit-wstep.enroll.json   audit-wstep.renew.json   audit-xcep.policy.json
```

## Notes

- Over WinRM or a locked-down host, run `Set-ExecutionPolicy -Scope Process Bypass -Force` first. Only the `CertificateServicesClient-Lifecycle-System` channel exists on Windows 11 26200 and Server 2022.
- The client shows no reason when the hub refuses issuance. Check the hub journal for `wstep: issuance ... failed` and the audit for `policy.violation` (a 2048-bit RSA request is refused by the default `Baseline` policy, `min_rsa_bits` 3072).
- Status: first run 2026-10-18 on Windows 11 and Server 2022; see the results doc.

- Real audit names: `wstep.enroll`, `wstep.renew`, `xcep.policy`; outcome `success|denied`
  (`internal/wstep/server.go`). Kerberos failures are `denied` rows of these, not a
  separate `wstep.kerberos.failure` event (see `docs/ops/WSTEP_FAILURES.md`).
- Windows caches policy for 8 h; always delete the policy cache before a pulse.
- The hub backdates NotBefore by 5 min, so skews under 5 min still work. `negative.ps1`
  enforces at least 6 and defaults to 10. The clock restore is in a `finally`; check
  `w32tm /query /status` before the next target.
- Time-based renewal (weeks granularity) stays "not verified live".
- A target you cannot run: mark its matrix row `BLOCKED` with the reason; the ticket stays `todo`.
- PowerShell syntax check on a host with `pwsh` or Windows:
  `[scriptblock]::Create((Get-Content .\collect-client.ps1 -Raw)) | Out-Null`
