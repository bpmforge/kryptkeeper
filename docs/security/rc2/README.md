# Kryptkeeper v0.9.0-rc.2 security re-scan (2026-10-10)

Target: RC2 commit `6200a0d` (branch `kk/rc2-security-scan`). Baseline: RC1 re-scan at `d74edf3`
(`docs/security/rc1/`, which FAILED on one HIGH). Code diff reviewed: `git diff d74edf3 6200a0d`
(185 files, +10.3k/-0.8k; 130 in the scoped globs, of which about 60 non-test Go files).
Artifacts scanned: `dist/` binaries (12/12 built with go1.26.9), SBOM `sbom_0.9.0-rc.2.cdx.json`,
image `localhost/kryptkeeper:0.9.0-rc.2` (id `8e673afe...`, checked equal to the archive that grype scanned).

## VERDICT: PASS

The gate is: no open CRITICAL/HIGH, no regression of a fixed finding, every RC1 MEDIUM fixed or documented.

- **Open CRITICAL/HIGH: 0.** RC1-A-01 (HIGH) is fixed and live-probed (see `03-live-probes.md`).
- **RC1 MEDIUMs: 9 of 9 FIXED** (A-02, A-03, A-04, B-01, B-02, B-03, C-01, M-1, M-2), each with code, a test, and
  where reachable a live probe. M-1 is fixed in compose (pinned /32) and documented in the Helm chart
  (`values.yaml`, `templates/NOTES.txt`) because the chart cannot know the ingress CIDR.
- **No regression** of any earlier fix: `go test ./...` passes in 50 packages (incl. acme, cmp, ca, ocsp, bootstrap),
  and the dual-control, write-gate, key-mint-escalation, 403 and login-limiter probes were repeated live.
- **New findings: 0 CRITICAL, 0 HIGH, 0 MEDIUM, 5 LOW, 5 INFO/doc.** None blocks. Listed below.
- Tools: opengrep +6 slop hits and 0 security hits vs RC1; gitleaks 0 findings in the 53 new commits;
  govulncheck 0 reachable vulnerabilities on go1.26.9 in every analysable module; npm audit 0; grype 0 on the
  image and 1 known false positive on the SBOM (GO-2026-5932, unreachable, no fix); no CISA KEV hits.

### Non-blocking items (recommended before GA, none required for the gate)
1. RC2-N-07 (doc): CHANGELOG and the scheduler log line say a **pki-operator** can re-arm an `auto_renew` target;
   a pki-operator lacks `discovery.manage` and gets 403. Only pki-admin (or a custom role with both
   permissions) can. Operators upgrading from RC1 will follow wrong instructions.
2. RC2-N-01 (LOW): rate-limiter eviction costs 0.66 ms per new key under the global mutex once 100k keys are live.
3. Carry the still-open RC1 LOWs (list in `02-findings.md`) into a "Known limitations" entry in `SECURITY.md`; today
   only `CHANGELOG.md` and the RC1 reports record them.

## Counts
| Severity | Open at RC1 | Fixed in RC2 | Open at RC2 |
|---|---|---|---|
| CRITICAL | 0 | - | 0 |
| HIGH | 1 (A-01) | 1 | 0 |
| MEDIUM | 9 | 9 | 0 |
| LOW (RC1 new + residual) | 19 | 2 (C-02, U-1) | 17 carried (non-blocking) |
| LOW (new in RC2) | - | - | 5 (N-01..N-05) |

## Files
- `01-automated.md` - opengrep diff, gitleaks, govulncheck, npm audit, grype, KEV, go test
- `02-findings.md` - RC1 finding status table (code + test citations), new RC2 findings, checked-and-held list
- `03-live-probes.md` - live hub probes with the honest list of what was not exercised live
- `opengrep_rc2.{json,sarif,log}`, `raw/` - raw tool and probe outputs (secrets redacted; generated secrets were
  grep-checked absent from this directory before commit)

## Method
Read-only review of the RC1 to RC2 diff (egress stamps, certificate iterator, audit store, SIEM, keystore cache,
login KDF slots, limiter, clientip, Content-Disposition, placeholder check, migrations 000072/000073, compose, Helm,
release workflow), plus a live hub from the RC2 darwin/arm64 artifact (`KRYPTKEEPER_TLS_DISABLE=true`, random
secrets, six principals via `APP_API_KEYS_JSON`, admin login), stopped afterwards. No code was changed.
