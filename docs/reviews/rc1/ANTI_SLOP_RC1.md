# Anti-Slop Audit: Kryptkeeper v0.9.0-rc.1 (d74edf3)

Date 2026-10-10. Read-only audit, branch `kk/rc1-antislop`. Rules R-01..R-31.
Delta reviewed: `git diff a9288d2 d74edf3` (99 files, +5981/-1035). Prior reports:
`ANTI_SLOP_FINDINGS_2026-10-09.md`, `DEAD_CODE_FINDINGS_2026-10-09.md`.

## Verdict

**FAIL (one blocking item, a documentation fix; no HIGH/CRITICAL code slop).**

Blocking: **AS-03**. README.md:15, RELEASE_NOTES_v0.9.0.md (Highlights) and
FEATURE_VALIDATION_v0.9.md:75 claim agentless SSH discovery. The only code that
does it, `AgentlessSSHScanner`, has no production caller. The fix is a wording
change in three places, no code. After that the verdict is PASS.

Counts: 0 CRITICAL, 0 HIGH, 3 MEDIUM (AS-01..03), 6 LOW (AS-04..09), 2 INFO.

Tooling that ran: `deadcode -test` (39 unreachable, prior 43), `deadcode` without
tests (149, prior 155), `staticcheck ./...` (75 lines, 26 of them SA1019), `gofmt -l`
(4 files), `go list -m all` offline (rc=0), grep sweeps, a python LDR script. No
installs, no network. The `go list` run touched `go.sum`; it was reverted.

## Per-rule status

| Rule | Topic | Status | Note |
|---|---|---|---|
| R-01..R-04 | Error handling (empty catch, swallowed, etc.) | PASS | New code checks errors; `resolveDefaultCA` checks `ListCAs` before the emptiness test (`startup_ca.go:56`). No empty catch in `ui/src` or Go. |
| R-05..R-08 | Abstraction slop | PASS | `siemAuditProvider` is a real decorator with two behaviours (counter + forward), not a pass-through. |
| R-09..R-11 | Defensive bloat | PASS | `clientip.New` skips malformed CIDRs and degrades to "trust nobody". Justified for a PKI. |
| R-12..R-16 | Comment slop | PASS | Comments in new files state why (threat, ordering, spec). `certificate_ca_provider.go:251` is a correct history note. |
| R-17..R-20 | Structural | FINDINGS | AS-02 (duplicated JWK RSA decode, two policies); AS-08 (gofmt). |
| R-21 | Slopsquatting | PASS | See "Dependency provenance" below. |
| R-22 | Architectural privilege escalation | PASS | `authz_grant.go` enforces grant-only-what-you-hold. Pinned-cert renewal fails closed without a registry. |
| R-23 | Credential leakage | FINDINGS | AS-01 (placeholder keystore passphrase passes the length gate). No keys or tokens in code or history grep. |
| R-24 | Docstring inflation | PASS | LDR 0.36 to 0.84 on 8 sampled files (below). Dense but specific. |
| R-25 | Phantom imports | FINDINGS | AS-04 (`vault.go` still suppresses unused imports). |
| R-26 | Disconnected pipelines | FINDINGS | AS-07 (5 DEAD-005..009 items remain). SIEM and upstream renewal are fixed. |
| R-27 | Stubs returning success | PASS | `publicKeyBits` stub is fixed. Remaining "not implemented" strings return errors (`byok_targets.go:108,110`). |
| R-28 | LLM output without validation | PASS | MCP writes are proposal-only. Not re-audited here (see OWASP-LLM report). |
| R-29 | Prose padding | PASS | Release notes are short and specific. |
| R-30 | Library-shaped reimplementation | FINDINGS | AS-02, AS-09. No `VENDORED.md`; no vendored dirs found. |
| R-31 | Confabulated analysis | FINDINGS | AS-03. 19 of 20 spot-checked claims hold (table below). |

## Findings

### AS-01 [MEDIUM] `env.example` ships a known keystore passphrase that the hub accepts
- Confidence 85. Rules R-23 (credential leakage), R-21 adjacent (insecure default).
- `env.example:100`
```
KRYPTKEEPER_KEYSTORE_PASSPHRASE=change-me-to-a-different-strong-secret
```
- The string is 38 bytes. The only length gate in `auth_validation.go` is 32 bytes,
  and `main.go:153` only checks the value is non-empty. Compose requires the variable
  (`docker-compose.yml:27`, `${...:?}`), but `cp env.example .env` satisfies that.
  `APP_BOOTSTRAP_TOKEN=change-me-to-a-strong-secret` is 27 bytes, so it fails the
  32-byte rule and forces the operator to edit it. The passphrase has no such forcing
  function. An operator who fixes the token and skips the passphrase runs a hub whose
  CA keys at rest are protected by a public string. The release notes say to set both
  values, which lowers the risk but is not enforcement.
- Fix: refuse a passphrase or token that starts with `change-me` at startup (one
  shared check, one test). Or ship `env.example` with the line commented out.
  Effort XS. Module `cmd/kryptkeeper` + `internal/bootstrap`.

### AS-02 [MEDIUM] Hand-rolled RS256 JWT/JWKS verifier with thin direct negative tests
- Confidence 80. Rules R-30, R-19.
- `internal/bootstrap/auth_jwks.go:22` `validateOIDCRS256JWT` parses the JWT, pins
  `alg == "RS256"`, resolves a JWK by `kid`, and calls `rsa.VerifyPKCS1v15`. JWKS
  caching lives in `auth.go:72` (`managedOIDCJWKSCache`). `go-jose` and `golang-jwt`
  appear only in `go.sum`, so there is no vetted JOSE library behind it.
```go
alg, _ := header["alg"].(string)
if alg != "RS256" {
    return "", "", fmt.Errorf("unsupported jwt alg")
}
```
- What is good: `alg` is pinned (no alg-none or HS256 key-confusion path), `exp` is
  required, `nbf` is checked, issuer and audience are enforced when configured, the
  exponent is bounds-checked, and refetch on an unknown `kid` is throttled and
  coalesced (`TestJWKS_UnknownKidRefetchIsThrottled`, `...ConcurrentUnknownKidCoalesces`).
- What is missing: no unit test calls `validateOIDCRS256JWT` with `alg:none`, an
  HS256 token signed with the public modulus, a wrong `aud`, or an expired token. The
  tests that call it directly cover `nbf` only (`auth_hardening_test.go:115`). A wrong
  signing key and a wrong issuer are covered through the login flow
  (`auth_oidc_login_test.go:435,464`), not the bearer path (`auth.go:363`).
- Duplication: the JWK RSA decode exists twice with different policy.
  `acme/jws.go:239` rejects moduli under 2048 bits. `auth_jwks.go` (`resolveRSAPublicKeyByKID`)
  has no modulus floor and allows exponent 3.
- Only RS256 is accepted, so an IdP that signs with ES256 or PS256 fails closed.
  Fail-closed is correct; it is a functional limit that the release notes do not name.
- Fix: add a 6-row negative table test (alg none, alg HS256, bad signature, wrong aud,
  expired, missing kid) on the bearer path. Share one JWK-RSA decoder with a 2048-bit
  floor. Evaluate `go-jose` v4 for v0.10. Effort S.

### AS-03 [MEDIUM, BLOCKING] Release docs claim agentless SSH discovery that nothing runs
- Confidence 78. Rule R-31 (claim the code does not support).
- Claims:
  - `README.md:15`: "network scanning, SSH/WinRM agentless, CT log monitoring"
  - `RELEASE_NOTES_v0.9.0.md` Highlights: "WinRM and SSH agentless discovery"
  - `FEATURE_VALIDATION_v0.9.md:75`: `Agentless SSH discovery/install | LIVE | tests/live/ssh-install/run.sh`
- Evidence against: `internal/agentdiscovery/agentless_ssh.go:82 NewAgentlessSSHScanner`
  and `:91 Scan` are unreachable in `deadcode ./...` and have no non-test caller
  (`grep -rn AgentlessSSH cmd internal` outside tests returns only the definitions).
  `tests/live/ssh-install/` exercises SSH install and `ssh-keyscan` host-key capture;
  its README mentions discovery only in a WinRM cross-reference. The network scanner
  does record SSH banners and host-key algorithms (`discovery_provider.go:53-57`), but
  that is endpoint discovery, not an agentless certificate walk over SSH.
- Same family, not blocking: `ParseJKSCerts`, `ParsePKCS12Certs`,
  `ParseKubeconfigCerts`, `ScanKeystoreFile` (`agentdiscovery/keystores.go`) are also
  unwired, and `FEATURE_VALIDATION` does not label them NOT-WIRED.
- Fix: change the three lines to "WinRM agentless discovery; SSH install" (or wire
  `AgentlessSSHScanner` into a scan job and add a live test). Re-label FEATURE_VALIDATION:75
  to "Agentless SSH install | LIVE; SSH cert discovery | NOT-WIRED". Effort XS.

### AS-04 [LOW] Phantom imports kept alive with `_ =` (still present from S-02)
- Confidence 90. R-25. `internal/keystore/vault.go:467-473`
```go
// Suppress unused import warnings for packages only used in tests.
var (
	_ = rand.Reader
	_ = elliptic.P256()
	_ = sha256.New
	_ = big.NewInt
)
```
- Fix: delete the block and any import left unused. Effort XS.

### AS-05 [LOW] Production symbol that exists for a test double (still present from S-03)
- Confidence 85. R-27 marker. `internal/bootstrap/certs_summary_db_provider.go:29`
  `var errDBCertSummaryStoreUnimplemented = errors.New("db cert summary store is unimplemented")`.
  Only caller: `certs_summary_store_test.go:39`. Fix: move it into the test file. XS.

### AS-06 [LOW] Vacuous test (still present from S-04)
- Confidence 85. `internal/cloudinventory/aws_acm_test.go:18`
```go
func TestACMConnectorNotNilWithValidConfig(t *testing.T) {
	_ = ACMConnector{}
}
```
- Asserts nothing; the name promises config validation. Fix: delete, or assert the
  `NewACMConnector` error paths. XS.

### AS-07 [LOW] Five unwired features from the dead-code report remain
- Confidence 85. R-26. `deadcode ./...` (no tests) still lists:
  `ctmonitor/store.go:117 Store.List`, `:152 Store.Acknowledge` (DEAD-005);
  `agentdiscovery/keystores.go`, `configparser.go:78`, `agentless_ssh.go` (DEAD-006);
  `sshkeys/inventory.go:57 NewInventory` (DEAD-007);
  `notifications/delivery/delivery.go:378 NewThresholdEvaluator` (DEAD-008);
  `adsync/adsync.go:127 RegisterEnrollmentService` (DEAD-009).
- Also `bootstrap/finding_exception_store.go:132 newFindingExceptionID` has no
  non-test caller. That one is disclosed (below), the others are mostly not.
- Fix: for v0.10, wire or delete. For the RC, label the rows in FEATURE_VALIDATION
  (feeds AS-03). Effort S per item.

### AS-08 [LOW] Formatting and linter residue
- Confidence 95. `gofmt -l` reports `internal/bootstrap/certificate_provider.go`,
  `internal/bootstrap/handlers_dashboard.go`, `internal/discovery/scanner/scanner_test.go`,
  `internal/sshkeys/ca_test.go`.
- `ui/src/index.css.bak` is tracked (`git ls-files`).
- UI keeps four `// eslint-disable-line react-hooks/exhaustive-deps`: `Alerts.tsx:56`,
  `Discovery.tsx:96`, `Certificates.tsx:545`, `CAs.tsx:208` (S-06, unchanged). 12
  suppressions total, 6 of them intentional `@ts-expect-error` type tests.
- Fix: `gofmt -w` the four files, `git rm` the `.bak`. XS.

### AS-09 [LOW] ACME EC JWK parse uses deprecated raw-coordinate API
- Confidence 80. R-30. `internal/acme/jws.go:214-215`
```go
pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
```
- `staticcheck` SA1019: `ecdsa.PublicKey.X/Y` deprecated since Go 1.26, and
  `elliptic.Curve.IsOnCurve` deprecated since Go 1.21 (26 SA1019 lines in total,
  also `acme/store_sqlite.go:242`, tests). The on-curve check is correct today.
  Fix: build `0x04||X||Y` and call `ecdsa.ParseUncompressedPublicKey` (Go 1.25+),
  which does the check. Also `main.go:134` SA4023 is the PKCS#11 default-build stub
  always returning an error; harmless, add a `//lint:ignore`. XS.

### AS-10 [INFO] Hand-rolled in-memory TTL maps on security paths
- Confidence 75. R-30. `auth_saml_guard.go` (request and replay maps), `cmp/replay.go:28`,
  the OIDC login-state store, and the rate limiter each keep their own map plus
  `sweepExpired`. They are bounded (4096 and 8192 entries) and fail closed at the cap.
  They are per-process, so replay protection does not span hub replicas; the release
  notes already disclose "in-memory refresh tokens and replay caches".
- No action for RC. v0.10: one shared bounded TTL set, shared store for HA.

### AS-11 [INFO] Logic-density and docstring check on new code
- Comment-heavy by house style, but every sampled block states a threat or ordering
  constraint. No exported-symbol docstring restates its signature. See LDR table.

## Fixed since 2026-10-09

| Prior | Item | Evidence at d74edf3 |
|---|---|---|
| ANTI S-01 | `publicKeyBits` stub returned 0 | `certificate_ca_provider.go:1140` now `return ca.PublicKeyBits(cert.PublicKey)`; `:251` records the history |
| DEAD-001 | SIEM never received events | `audit_events.go:~98 siemAuditProvider.AppendEntry` calls `EmitFromAuditEntry`; `main.go:247` wraps via `WithSIEMForwarding`; no longer in deadcode |
| DEAD-002 | Renewal executor lacked connector registry | `renewal_executor.go:186 WithEnvConnectorRegistry` (lazy store, per-renewal rebuild, fail closed when pinned and missing) |
| DEAD-003 | Finding exceptions cannot be created | Disclosed instead: RELEASE_NOTES "Not in v0.9", `openapi.yaml:581,605`, FEATURE_VALIDATION:115 (HIDDEN). Treated as resolved-by-disclosure. |
| DEAD-004 | DigiCert/EST/SCEP/WSTEP connectors inert | Disclosed instead: FEATURE_VALIDATION:100 (NOT-WIRED), RELEASE_NOTES "Not in v0.9", README:452 |
| ANTI S-05 (b) | Comment in `auth_rate_limit.go` denied an existing trust check | Rate limiter now delegates to `internal/clientip`; file shrank 98 lines |
| (new) | `request_body.go` caps unauthenticated JSON bodies | 5 caps, 413 envelope; used in auth, agent and SCIM handlers |

Still present from the prior reports: S-02 (AS-04), S-03 (AS-05), S-04 (AS-06), S-06 (AS-08),
DEAD-005..009 (AS-07).

## Dependency provenance (R-21)

- Root `go.mod`: 24 direct requirements. `go list -m all` succeeds offline (rc=0), so
  every module and version is in the module cache with a `go.sum` hash. All names are
  well-known upstream projects: `ThalesGroup/crypto11`, `aws-sdk-go-v2` (+`config`,
  `service/acm`, `service/kms`), `beevik/etree`, `cloudflare/circl`, `go-ldap/ldap/v3`,
  `go-pdf/fpdf`, `jackc/pgx/v5`, `jcmturner/gokrb5/v8` + `goidentity/v6`,
  `mark3labs/mcp-go`, `russellhaering/gosaml2` + `goxmldsig`, `smallstep/pkcs7`,
  `go.mozilla.org/pkcs7`, `spiffe/go-spiffe/v2`, `tink-crypto/tink-go/v2`,
  `golang.org/x/{crypto,sys}`, `google.golang.org/grpc`, `modernc.org/sqlite`,
  `software.sslmate.com/src/go-pkcs12`. Every direct dep has at least one import
  in `cmd/` or `internal/` (fewest: `etree`, `fpdf`, `goidentity` with 1 file each).
- Two PKCS#7 libraries are in use: `go.mozilla.org/pkcs7` (archived upstream) and
  `smallstep/pkcs7` (maintained fork). Both are imported (`scep/server.go`, `est/server.go`,
  `connectors/*`). Not slopsquatting, but consolidating on the fork is cheap. Noted, no finding.
- Sub-modules: `terraform-provider-kryptkeeper` requires `hashicorp/terraform-plugin-framework`
  v1.19.0 (real). `plugins/*` and `tests/live/protocols/estcheck` use only the local
  `replace` to `sdk/delivery-go`.
- `ui/package.json`: 15 dependencies and 20 devDependencies. Every one is present in
  `package-lock.json` with a `registry.npmjs.org` URL and an integrity hash. Lock
  version drift: `react-router-dom` ^7.18.2 resolves to 7.18.4, `typescript-eslint`
  to 8.58.1, `vite` to 8.0.7 (all inside their ranges). `@base-ui/react` and
  `shadcn` are the real packages. Confidence 85 (registry existence inferred from
  lock metadata, not re-queried).

## Doc-claim spot check (22 rows)

| # | Claim (source) | Result |
|---|---|---|
| 1 | Autopilot 29/29 (RELEASE_NOTES) | 29 `PASS "` call sites in `tests/live/autopilot/run.sh` (count of sites, not a run) |
| 2 | Agent 18/18 | `tests/live/agent/run.sh` has `PASS` lines; count not independently confirmed (5 matches of `PASS`, harness uses another helper). Not verified. |
| 3 | Smoke 331/331 | Matches FEATURE_VALIDATION:23; run results not re-executed here |
| 4 | Key export needs second approver, `KRYPTKEEPER_KEY_DUAL_CONTROL=false` opts out | Variable read in 3 non-test files |
| 5 | `AUTH_MODE=jwt/oidc` bearer read-only until `APP_AUTH_ROLE_CLAIM`/`APP_AUTH_ROLE_MAP_JSON` | Both in `auth_role_map.go`, `auth_config.go`; `TestSessionJWTWithoutRoleClaimRejected` |
| 6 | Secrets under 32 bytes are startup errors | `auth_validation.go` `minHS256SecretBytes = 32`, `minBootstrapTokenChars = 32` |
| 7 | OIDC without issuer and audience is a startup error | `TestValidationReport_OIDCRequiresIssuerAndAudience` |
| 8 | `MULTI_TENANCY` refused without `...EXPERIMENTAL=accept-risk` | `tenancy_experimental.go` |
| 9 | Compose needs keystore passphrase distinct from token | `docker-compose.yml:27` `:?` guard |
| 10 | Behind a proxy set `APP_TRUSTED_PROXY_CIDRS` | `clientip.go:21`; default trusts nobody |
| 11 | Archives for linux amd64/arm64, darwin arm64 only | `.goreleaser.yaml` ignores darwin amd64 for 4 binaries |
| 12 | deb/rpm for hub, CycloneDX SBOM, keyless cosign | `.goreleaser.yaml` `formats: [deb, rpm]`, `sboms:`; `release.yml` `id-token: write`, cosign-installer |
| 13 | Four binaries incl. certmanager and mcp | `.goreleaser.yaml` ids present |
| 14 | SCEP one-time challenges; static challenge and `/scep/mscep_admin` removed | `KRYPTKEEPER_SCEP_ENABLED` in 3 files; `mscep_admin` has 0 hits in `cmd` and `internal` |
| 15 | Retry 5 attempts; `pending_installs`, `gave_up_installs`, `certificate.renew_execute_gave_up` | All three identifiers exist (1 file each) |
| 16 | Env knobs: 22 variables named in CHANGELOG [0.9.0] | All 22 found in non-test source (counts above) |
| 17 | Migration 000070/000071 `verify_host_port` | `000071_managed_targets_verify_host_port.up.sql` in diff |
| 18 | Go 1.26.9, `x/net` v0.60.0 | `go.mod`: `toolchain go1.26.9`, `x/net v0.60.0` |
| 19 | Vault and GCP KMS stores "no tests" | No `vault_test.go`; `cloudkms_gcp.go` has no test file. True. |
| 20 | UI has no browser end-to-end tests | No Playwright config or `ui/e2e`. True. |
| 21 | SSH agentless discovery | **FALSE as worded**, AS-03 |
| 22 | Files cited exist (TENANCY_POSTURE, OWASP_TRACKER, final-report, UAT_PLAN, deployment, AIRGAP_INSTALL, DELIVERY_PLUGINS, `.goreleaser.yaml`, SECURITY.md) | All 9 present |

Result: 1 false claim (21), 1 unverified count (2), the rest hold. The notes are
notably candid (they list what is mock-only, emulator-only, or pending), which is the
opposite of padding. The release-notes statement that the image push "has not been
exercised end to end" matches the workflow.

## Tests on security paths

Sampled for assertions that deny, not just `err == nil`. All meaningful:
`clientip_test.go` (3 tests with table cases for spoofed XFF, untrusted peer),
`auth_saml_test.go:628` signature wrapping (also proves the attack is live against an
unsafe SP), `auth_oidc_login_test.go` (replay, expiry, wrong key, wrong issuer, rate
limit, 11 proxy-trust variants), `authz_grant_test.go`, `auth_saml_guard_test.go`,
`startup_ca_test.go` (fail-closed policy gate). Gaps: AS-02 (bearer RS256 negatives);
no `request_body_test.go`, though `auth_failclosed_test.go` references the cap.
Vacuous: AS-06 only.

## LDR (logic / (logic + overhead), python heuristic, blank/comment/import/brace = overhead)

| File | Logic | Overhead | LDR |
|---|---|---|---|
| `internal/clientip/clientip.go` | 46 | 74 | 0.38 |
| `internal/bootstrap/request_body.go` | 28 | 50 | 0.36 |
| `internal/bootstrap/renewal_scheduler.go` | 408 | 392 | 0.51 |
| `internal/bootstrap/audit_events.go` | 63 | 77 | 0.45 |
| `internal/bootstrap/authz_grant.go` | 86 | 77 | 0.53 |
| `internal/bootstrap/auth_saml_guard.go` | 79 | 89 | 0.47 |
| `cmd/kryptkeeper/startup_ca.go` | 34 | 48 | 0.41 |
| `ui/src/pages/CloudKeys.tsx` | 361 | 69 | 0.84 |

All above the 0.3 slop threshold. The two lowest files are small and carry
threat-model comments, which CLAUDE.md asks for.

## Not covered

- Did not re-run Go or UI test suites (read-only audit; gate results belong to the
  other RC reviewers). Did not query npm or the Go proxy live.
- OWASP/security depth of the new auth code is the security reviewer's scope; this
  report only flags test and provenance gaps (AS-02).
