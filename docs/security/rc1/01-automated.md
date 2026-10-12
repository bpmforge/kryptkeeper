# Automated results (RC `d74edf3`)

## Opengrep 1.30.2 + bpm-rulepacks (owasp, secrets, slop, framework, house)
Same command and targets as 2026-10-09 (`cmd internal sdk plugins ui/src`, `LC_ALL=en_US.UTF-8`).
Outputs: `opengrep_rc1.json|sarif|log`.
- 2026-10-09: 288 findings (713 files). RC1: 290 findings (746 files, 80 rules applied).
- Diff keyed on (rule, path, matched text): 9 added, 7 removed. All 9 added are slop/code-health
  (`fallback-hides-failure-go` x7, `empty-catch-go` x2). No new security-rule hit.
- The 13 security-rule hits (weak-hash x3, tls-verify-disabled x7, hardcoded-secret x1, generic-secret x1,
  UI PEM placeholder x1) are identical to the audited, triaged-FP set from 2026-10-09 (cipher audit, discovery
  scanner posture probes, fingerprint-pinned verify, constant names). Classification: previously-known FP.
- framework/react rules: 0 hits.

## gitleaks (full history, `gitleaks git`, redacted)
30 findings over 1,569 commits (2026-10-09: 26 over 1,633 commits incl. other refs). 4 are in commits
since the baseline: `auth_hardening_test.go:16` and `mcpserver/transport_http_test.go:18` (test constants
`0123456789abcdef...`), `tests/smoke/run.sh:586` (smoke-test hash/verifier, same pattern as 4 older hits).
All FP. No live secret. Raw: `raw/gitleaks_rc1.json`.

## govulncheck (every module)
| Module | Local toolchain go1.27.1 | go1.26.9 (CI pin) |
|---|---|---|
| root | 11 reachable stdlib vulns (GO-2026-6599..6617: net/http, http2, crypto/tls, textproto, html/template), fixed in 1.27.2; 0 third-party | 0 |
| terraform-provider | 8 stdlib vulns | 0 |
| sdk/delivery-go, plugins/{example,f5,citrix} | 0 | - |
| ui (go.mod only) | no vulns | - |
| tests/live/protocols/estcheck | not analysable (missing module `globalsign/est`, test tool only) | - |
Finding **M-2**: the `dist/` RC binaries were built with go1.27.1 (`go version -m` says go1.27.1), so release
artifacts built this way ship 11 reachable stdlib CVEs. The container image is built on go1.26.9 and is clean.
Rebuild release binaries with the pinned CI toolchain (or Go >= 1.27.2). Known residual of the 2026-10-09 note.

## npm audit --omit=dev (ui/)
0 vulnerabilities (57 prod deps). Better than 2026-10-09 (react-router-dom fixed).

## grype
- SBOM `sbom_0.9.0-rc.1.cdx.json`: 1 match, `golang.org/x/crypto v0.57.0` GO-2026-5932 (openpgp "unsafe by design",
  no fix version). `go list -deps` shows `x/crypto/openpgp` is not imported; govulncheck "not called". FP.
- Image `localhost/kryptkeeper:0.9.0-rc.1` (OCI archive, distroless static, nonroot, Go stdlib 1.26.9): **No vulnerabilities**.
- Fixable HIGH/CRITICAL: none. CISA KEV hits: none (grype `knownExploited` empty on all matches).
