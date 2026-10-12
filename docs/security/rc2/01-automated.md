# Automated results (RC2 `6200a0d`)

## Opengrep 1.30.2 + bpm-rulepacks (owasp, secrets, slop, framework, house)
Same command and targets as RC1 and 2026-10-09 (`LC_ALL=en_US.UTF-8`, `cmd internal sdk plugins ui/src`, no registry rules).
Outputs: `opengrep_rc2.json|sarif|log`; diff in `raw/opengrep_diff_vs_rc1.txt` (key = rule, path, matched text).
- RC1: 290 findings (1124 files tracked). RC2: **296 findings** (1161 files), 232 rules.
- **6 added, 0 removed**, all `bpm-slop-fallback-hides-failure-go`: `anomaly_wiring.go`, `slo_wiring.go`,
  `managed_target_store.go`, `certificate_index.go` x2 (a revoked-filter return and a hydrate error), `principal_reserved.go`.
  Triage: four are benign (bool/predicate returns). `principal_reserved.go` is the deliberate fail-open on a user-store
  error (RC2-N-02). `anomaly_wiring.go`/`slo_wiring.go` return nil on a probe error (health wiring). No new security-rule hit.
- The 13 security-rule hits (weak-hash x3, tls-verify-disabled x7, hardcoded-secret x1, generic-secret x1, UI PEM placeholder x1)
  are identical to the triaged false-positive set of 2026-10-09 and RC1. `framework/react`: 0 hits.

## gitleaks 8.30.1 (`gitleaks git --log-opts=d74edf3..6200a0d --redact`)
**0 findings in 53 new commits** (1.76 MB scanned). Raw: `raw/gitleaks_rc2.log|json`. (RC1's four test-constant
false positives are in older commits and out of this range.)

## govulncheck v1.8.0, GOTOOLCHAIN=go1.26.9 (the CI pin), vuln DB updated 2026-10-08
| Module | Result |
|---|---|
| root `kryptkeeper` | **0 affecting the code**; 1 in a required module not called: GO-2026-5932 (`golang.org/x/crypto@v0.57.0` openpgp, no fix) |
| terraform-provider-kryptkeeper, sdk/delivery-go, plugins/{example,f5,citrix} | No vulnerabilities |
| ui (go.mod only) | no packages |
| tests/live/protocols/estcheck | not analysable (missing module, test tool only; same as RC1) |
RC1 M-2 (11 reachable stdlib CVEs on go1.27.1) is closed: all 12 shipped binaries are go1.26.9 (`go version -m`).
Raw: `raw/govulncheck_*.txt`. Note: the local default toolchain is go1.27.1; scans used the pinned one.

## npm audit --omit=dev (ui/)
**0 vulnerabilities** (57 production deps, 655 total). `raw/npm-audit.json`.

## grype (DB built 2026-10-10 06:30Z)
- SBOM `sbom_0.9.0-rc.2.cdx.json`: **1 match**, `golang.org/x/crypto v0.57.0` GO-2026-5932, severity Unknown, no fix version.
  False positive in practice: `openpgp` is not imported and govulncheck reports it as not called.
- Image `localhost/kryptkeeper:0.9.0-rc.2` (`podman save --format oci-archive`; archive image id equals
  `8e673afebb4d...` from `rc2/image-id.txt`; Debian-12 userland per grype, Go stdlib 1.26.9): **No vulnerabilities**.
- Fixable HIGH/CRITICAL: none. **CISA KEV: none** (grype `knownExploited` empty on both outputs). `raw/grype_*.{json,txt}`.

## Test suite
`GOTOOLCHAIN=go1.26.9 go test ./...`: **exit 0, 50 packages ok, 0 failed** (acme, cmp, ca, ocsp, est, scep, bootstrap,
keystore, ratelimit, clientip, agentinstall, db, plugin conformance and the offline tests/live suites).
Focused run of the RC1-fix tests (`TestDiscoveryOperator...`, `Stamp`, `GrantBinding`, `Oversize`, `Threshold`,
`VerifyHostPort`, `NamePolicy`, `ContentDisposition`, `Evict`, `SIEM`, `Users`): 69 passed, 0 failed.
Raw: `raw/gotest_all.txt`, `raw/gotest_focus.txt`. Postgres-backed migration tests (`migrate_renewal_status_postgres_test.go`)
need `KRYPTKEEPER_TEST_POSTGRES_DSN` and skip without it; the sqlite 000073 up/down test ran.
