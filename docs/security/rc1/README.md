# Kryptkeeper v0.9.0-rc.1 security re-scan (2026-10-10)

Target: RC commit `d74edf3` (branch `kk/rc1-security-scan`). Baseline: audit of 2026-10-09 at `6d81d72`
(`docs/security/final-report.md`). Code diff reviewed: `git diff 6d81d72 d74edf3` (~314 files).

## VERDICT: FAIL

One new HIGH (RC1-A-01) blocks the gate. No regression of a previously fixed CRITICAL/HIGH was found
(FG-1, FG-2, FG-3, FG-5, FG-7, FG-9 spot-checks hold, with FG-2 gaps below at MEDIUM).

### Blocking list
- **RC1-A-01 HIGH (NEW):** a `discovery.manage` principal (built-in `discovery-operator`) can arm `auto_renew` on a
  target whose host equals any hub certificate's CN/SAN, with a `credential_ref` they did not create. The scheduler
  then renews that certificate and pushes the new certificate and private key to the device or cluster the credential
  points at (k8s, f5, citrix, iis, ssh, plugin). No ownership, tenant or credential-existence check. See `02-findings.md`.

### Counts (new vs known residual)
| Severity | NEW | Known residual / incomplete earlier fix |
|---|---|---|
| CRITICAL | 0 | 0 |
| HIGH | 1 (A-01) | 0 |
| MEDIUM | 9 (A-02, A-03, A-04, B-01, B-02, B-03, C-01, M-1, M-2) | 0 |
| LOW | 12 (A-05, A-07, A-08, A-09, B-04, B-05, B-07, B-08, C-02, C-05, C-06, U-1) | 7 (A-06, B-06, C-03, C-04=B-09, I-1, I-2, M-3) |
| INFO | ~14 | - |

B-01 and B-02 are gaps in the FG-2 fix (dual control), not a regression of its tested paths.

## Files
- `01-automated.md` - opengrep diff, gitleaks, govulncheck, npm audit, grype, KEV
- `02-findings.md` - manual review findings (all severities), FG spot-check table, checked-and-held list
- `03-live-probes.md` - live hub probe transcript summary
- `opengrep_rc1.{json,sarif,log}`, `raw/` - raw tool outputs (secrets redacted)

## Method
Opengrep 1.30.2 with bpm-rulepacks (same flags as 2026-10-09); gitleaks full history; govulncheck for every module;
npm audit; grype on SBOM and on the image (OCI archive); three parallel read-only code reviews of the new code
(renewal/egress; authn/authz/web; protocols/keys/UI) plus own live probes against a local hub
(`KRYPTKEEPER_TLS_DISABLE=true`, random secrets, stopped afterwards). `go test` for bootstrap, clientip, egress, sshkeys,
mcpserver, discovery (all ok) and acme/cmp/ca/ocsp (349 tests ok).

## Recommended fix order
1. A-01 (gate `auto_renew`/`credential_ref`/install fields behind certificate.renew + approval; validate credential; scheduler cert-vs-target authorization).
2. B-01/B-02 (dual-control identity binding), A-03 (install profile from target, not request body), A-04 (egress guard on verify dial), B-03 (body cap on SPIFFE route), C-01 (CN under name policy), M-1 (set trusted proxy CIDRs in shipped compose/helm or key limiter on more than IP), M-2 (build release with CI-pinned Go >= fixed).
