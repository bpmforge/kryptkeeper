# Live validation W26-13: WSTEP/XCEP matrix (v0.14 kit, run for v1 on 2026-10-18)

Date: 2026-10-18. Hub: `lab-hub` (192.0.2.106), build `qa/v1-final` at `936b3c7b` (v1 QA upgrade, 12:11Z).
Kit: `tests/live/wstep/matrix/`. Evidence: `docs/release/proof-pack/windows-v1/`.
Rows follow actual build numbers, not marketing names. lab-win11 reports 10.0.26200 (25H2), not 24H2 (26100).

## Verdict: PARTIAL - enroll and template filter PASS; renew and post-fix skew re-run NOT RUN

First pass (12:15Z-12:40Z, hub `936b3c7b`): enroll refused, product defect WSTEP-RSA2048 (below). Fixed in `eb765c4d` + `11faa7c4`
(XCEP advertises the key size the issuance policy accepts); lab-hub was upgraded. Second pass (~13:00Z, hub at `11faa7c4`): both
members enrolled `CN=<host>.corp.example.test`, RSA-3072, in 6 s with no manual action (`/xcep 200`, `/wstep 200`; audit rows
`wstep.enroll success` and `xcep.policy success offered=[KKMachine(min_key=3072)]`). The kit's `hub-checks.sh` passed for both
(2 enroll rows each: one from the lead's earlier pulse at 13:00Z, one from the kit run at ~13:03Z after deleting the cert and the
`X509Enrollment` cache).

Renew and the skew re-run need hub writes or a clock change that the session's permission gate refused in the second pass (it
refused the template PATCH needed for the revision bump, even with the lead's relay that it was authorized). Marked NOT RUN.

## Matrix

| OS (build) | Enroll (GPO, no manual action) | Renew (`wstep.renew` + predecessor) | Template filter (user tmpl not offered) | Skew > 5 min refused |
|---|---|---|---|---|
| Windows 11 Enterprise (26200), lab-win11 | PASS (second pass; first pass FAIL, RSA-2048 vs Baseline) | NOT RUN (template revision bump refused by gate) | PASS | PASS pre-fix 12:36Z; post-fix re-run NOT RUN |
| Windows Server 2022 Standard (20348), lab-ws22 | PASS (second pass; first pass FAIL, same refusal) | NOT RUN | PASS (machine list is KKMachine only; user-context list measured on lab-win11) | PASS pre-fix 12:39Z; post-fix re-run NOT RUN |
| Windows Server 2025 Standard (26100), lab-dc01 / lab-ca01 | BLOCKED: see note 1 | BLOCKED | BLOCKED | BLOCKED: see note 2 |
| Windows 10 | BLOCKED: no ISO in the lab | BLOCKED | BLOCKED | BLOCKED |
| Windows Server 2019 | BLOCKED: no ISO in the lab | BLOCKED | BLOCKED | BLOCKED |

1. lab-dc01 and lab-ca01 hold no hub certificate and made no hub request in the window. Neither trusts the
   hub root (`LocalMachine\Root` has no "KK UAT Lab Root CA" on lab-dc01; a read-only `certutil -Template`
   against the hub hung there on the TLS trust prompt and was killed). Installing the root on a DC or
   the Enterprise CA, or forcing a pulse there, would change the CA role hosts, so it was not done.
2. The skew test shifts the clock 10 minutes. On the DC it moves the KDC and breaks Kerberos domain-wide,
   so it was not run on any Server 2025 host. Server 2025 stays BLOCKED until a member (non-DC, non-CA)
   Server 2025 VM exists.

## Measured evidence

Template filter. Machine context (admin, lab-win11 and lab-ws22) is offered only `KKMachine`
(`CT_FLAG_MACHINE_TYPE`, min key 2048). User context (`CORP\corp-user1`, scheduled task on lab-win11, policy cache
deleted first) is offered only `KKUser`. The hub logged `corp-user1@CORP.EXAMPLE.TEST - SPNEGO authentication succeeded`
for that request. Files: `*/templates-machine.txt`, `lab-win11-attempt1-baseline-rsa2048/templates-user.txt`.
(A first user-context query returned KKMachine from the local policy cache and never reached the hub; it was
discarded.)

Skew. +10 min on the client. Hub log: `SPNEGO validation error: ... KRB_AP_ERR_SKEW ... greater than 5m0s`, `POST /xcep 401`,
audit row `xcep.policy denied "Kerberos authentication failed"` (12:36:58Z lab-win11, 12:39:48Z lab-ws22). No certificate issued.
`hub-checks.sh <host> --skew-denied` printed `PASS denied wstep.enroll/xcep.policy rows`. Clock restored on both
(`w32tm /resync`, source LAB-DC01). Note the skew refusal alone proves little while enrollment is refused for a
different reason; the hub-side KRB_AP_ERR_SKEW line is what separates the two causes. Re-run after the fix.

Enroll failure (repro). On the hub:
`wstep: issuance for LAB-WIN11$@CORP.EXAMPLE.TEST failed: issuance policy "Baseline": rule allowed_algorithms: requested algorithm "RSA-2048" is not in the allow-list [...]`,
SOAP `s:Client` fault returned as HTTP 500, client side `RESULT enrolled=false after 120s`.

## Second pass enroll evidence (fixed hub)

| Host / OS | enroll seconds | Cert thumbprint | Key | .evtx / .etl / .pcapng |
|---|---|---|---|---|
| lab-win11 / 26200 | 6 | 782D4CE3BEDC9461CFC6983F0A2689A7463C3E23 | RSA-3072 | `lab-win11-enroll-ok/` (SHA256SUMS) |
| lab-ws22 / 20348 | 6 | 3E988FB42DAE3BBEE9BFEBABA51771BC1EAA0D54 | RSA-3072 | `lab-ws22-enroll-ok/` |

NotBefore is backdated 5 min, so "issued after 12:11Z" is proven by the audit rows (`hub-audit-wstep-2026-10-18.json`) not NotBefore.
The hub rows for the denied-audit change (`wstep.enroll denied` principal rows after the fix) were not exercised: no refusal occurred
in the second pass; check on the next refused request.

## Defects found

1. **WSTEP-RSA2048 (blocker).** `internal/xcep/server.go` `writePolicy` advertises `t.MinKeySize` (2048) from the template
   only and never reconciles it with the issuance policy (`min_rsa_bits` 3072, allowed algorithms). Windows complies,
   the hub refuses, the client shows no reason. Fix options: advertise `max(template, policy)` and offer only algorithms the
   policy allows, or ship the default template at 3072. Lab workaround (not applied, see below):
   `PATCH /api/v1/templates/<KKMachine id> {"min_key_size":3072}`. Do not loosen Baseline.
2. **Audit gap.** The refusal is recorded only as `policy.violation` (actor `policy-engine`, resource `pol-baseline`), without the
   principal or protocol. No `wstep.enroll denied` row is written, contrary to `docs/ops/WSTEP_AUTOENROLLMENT.md` (Audit).
   `xcep.policy success` rows are also not written (only denied), so the "hub audit success rows" check in the README cannot pass as written.
3. **Kit.** `capture.ps1` failed over WinRM (native `pktmon stop` stderr is terminating under `ErrorActionPreference=Stop`); fixed in this commit.
   `collect-client.ps1` exports only the `Lifecycle-System` channel on these builds (no `CertEnroll` channel exists); scripts also need
   `Set-ExecutionPolicy -Scope Process Bypass`.

## Defects status

Defects 1 and 2 are addressed by `eb765c4d`/`11faa7c4` (xcep.policy success rows now appear; verified in the audit). Defect 3 (kit) fixed.

## Why renew and the skew re-run were not completed

Renewal needs a template revision bump (any PATCH to `tpl-kkmachine-1791381901882432219`), then on each target
`certutil -f -PolicyServer * -PolicyCache delete; certutil -pulse`, then `hub-checks.sh <host> --renewed`. The PATCH, and the
re-run of `negative.ps1` (+10 min clock skew, restored in a finally), were refused by the session's permission gate. To finish,
the user must allow those Bash actions (or run them).

## Evidence per target (first attempt, failed; sizes under 5 MB)

Directory: `docs/release/proof-pack/windows-v1/<host>-attempt1-baseline-rsa2048/` (SHA-256 in `SHA256SUMS`; VM-side hashes match).

| Host / OS | enroll seconds | Cert thumbprint | .evtx | .etl / .pcapng | Renewal audit | Skew denied excerpt |
|---|---|---|---|---|---|---|
| lab-win11 / 26200 | none (120 s timeout) | none | `events-...Lifecycle-System_Operational.evtx` | `wstep.etl`, `wstep.pcapng` | NOT RUN | `xcep.policy denied` 12:36:58Z, KRB_AP_ERR_SKEW |
| lab-ws22 / 20348 | none (60 s timeout) | none | same | same | NOT RUN | `xcep.policy denied` 12:39:48Z |
| Windows 10, Server 2019 | BLOCKED: no ISO | | | | | |

Hub-side: `hub-journal-wstep-2026-10-18.txt`, `hub-audit-wstep-2026-10-18.json`, per-host `hub-checks.txt`.
The pre-existing `CN=lab-win11.corp.example.test` certificate (thumbprint CFC8FCDF..., issued 2026-10-07) was deleted from
`LocalMachine\My` to force a fresh enroll; it can be re-enrolled once the defect is fixed.
