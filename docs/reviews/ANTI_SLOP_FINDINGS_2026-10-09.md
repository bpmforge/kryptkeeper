# Anti-Slop Findings -- 2026-10-09

Scope: non-test Go + `ui/src` at main 6062c62. Read-only. Rules: ANTI_SLOP_RULES (stubs, phantom imports, docstring inflation, vacuous tests, hallucinated APIs).

## Summary

Overall slop level: LOW. `TODO|FIXME|XXX` in non-test Go: 0 hits. UI: 0 TODO/FIXME/"coming soon"; 13 lint/type suppressions (4 are `react-hooks/exhaustive-deps`; 6 are intentional `@ts-expect-error` type tests in `PageHeader.test.tsx`; others in `mocks/handlers.ts:5`, `components/ui.tsx:35`). Real defects are two stubs that return plausible values and one import-suppression hack.

Classification of the grep `not implemented|unimplemented|placeholder|stub` (60 hits): 52 are SQL placeholders (`?`/`$N`) or legitimate default-build stubs required by CONTRIBUTING (`peercred_other.go:11`, `agentdiscovery/windows_stub.go:14`, `cmd/kryptkeeper-agent/service_other.go:11`); 2 are honest `not implemented` errors (`keystore/byok_targets.go:108,110`: Azure/GCP BYOK return an error, not success); the rest are below.

Hallucinated-API spot check: `go doc crypto/x509.CreateCertificate` and `crypto/mlkem` resolve; `go list ./...` builds the 52 packages; ML-DSA OIDs in `keystore/mldsa.go:29` are the NIST 2.16.840.1.101.3.4.3.17/18/19 values. No phantom module found (go.mod direct deps all resolve; `go.mozilla.org/pkcs7` and `smallstep/pkcs7` are real). Confidence 80 (spot check, not exhaustive).

## Findings

### S-01 [MEDIUM] `publicKeyBits` is a stub that returns 0 for every certificate
- `internal/bootstrap/certificate_ca_provider.go:1093-1103`
```go
case x509.RSA:
    if pub, ok := cert.PublicKey.(*interface{}); ok { _ = pub }
    return 0 // will be filled by actual key inspection
default:
    return 0
```
- Dead type assertion (`*interface{}` can never match an x509 public key), no-op `_ = pub`, and a promise-comment never kept. Called at `:402,:607,:788,:932`, so every hub-issued certificate row stores `KeySizeBits: 0`. In a PKI inventory this under-reports key strength and can defeat weak-key (<2048) posture checks; `acme/server.go:914-917` then documents the 0 as "deliberately consistent" instead of fixing it.
- Fix: switch on `cert.PublicKey.(type)` -> `*rsa.PublicKey` `.N.BitLen()`, `*ecdsa.PublicKey` `.Curve.Params().BitSize`, `ed25519` 256; add a table test. `ca/key_strength.go:24 CheckPublicKeyStrength` already inspects keys -- reuse. Confidence 95. Effort: S. Module `internal/bootstrap`.

### S-02 [LOW] Phantom imports kept alive with `var _ =`
- `internal/keystore/vault.go:467-473`: `// Suppress unused import warnings for packages only used in tests.` then `_ = rand.Reader; _ = elliptic.P256(); _ = sha256.New; _ = big.NewInt`. In `vault.go` only `sha256.New()` (`:449`) is otherwise used; `crypto/rand`, `crypto/elliptic`, `math/big` are imported (`:28,29,40`) solely for the suppression. Test files import their own packages, so the comment is wrong as well as the hack being unneeded.
- Fix: delete the var block and the three imports. Confidence 90. Effort: XS. Module `internal/keystore`.

### S-03 [LOW] Production symbol that exists only for a test double
- `internal/bootstrap/certs_summary_db_provider.go:29` `var errDBCertSummaryStoreUnimplemented = errors.New("db cert summary store is unimplemented")`; sole reference is `certs_summary_store_test.go:39`. Dead in the shipped binary; reads like an unimplemented-stub marker.
- Fix: move to the `_test.go`. Confidence 85. Effort: XS.

### S-04 [LOW] Vacuous test on a connector constructor
- `internal/cloudinventory/aws_acm_test.go:15`: `TestACMConnectorNotNilWithValidConfig` body is `_ = ACMConnector{}` (comment: "just verify it compiles"). Name promises validation of config; asserts nothing. Counted via awk heuristic: 7 Test funcs with <=1 assertion across security-adjacent test files; the other 6 are legitimate no-panic/idempotence tests (`event_bus_test.go:140`, `renewal_scheduler_test.go:517`, `renewal_agent_driver_test.go:103,320`, `posture_scheduler_test.go:54`, `main_test.go:13`).
- Fix: delete or assert on `NewACMConnector` error paths. Confidence 85. Effort: XS.
- Positive: sampled security tests (`auth_rate_limit_test.go` 7 tests/16 assertions, `authz_grant_test.go` 6/22, `egress_test.go` 7/16, `ratelimit_test.go` 12/21) assert denied-path outcomes, not just `err == nil`. 27 `t.Skip` calls are all env-gated (live Postgres, SoftHSM, WinRM, LocalStack) except `ca/reconcile_test.go:180` (toolchain ML-DSA parse; documented).

### S-05 [LOW] Comment promises behaviour the code does not have
- `certificate_ca_provider.go:1099` "will be filled by actual key inspection" (see S-01).
- `bootstrap/auth_rate_limit.go:159-164` claims a missing trust check that now exists (see PATTERN P-01) -- the opposite failure: the code is better than its comment.
- No docstring inflation found on exported funcs in a 40-file sample; comments are long but specific (ticket-narration house style, not flagged).

### S-06 [INFO] Linter suppressions in UI
- `ui/src/pages/Alerts.tsx:56`, `CAs.tsx:208`, `Certificates.tsx:545`, `Discovery.tsx:113`: `// eslint-disable-line react-hooks/exhaustive-deps` on `cursor`/`filters` effects. Four copies of the same fetch-on-filter pattern suggest a shared `usePagedQuery` hook; suppression hides stale-closure risk. Confidence 75. Effort: M. Module `ui/src/pages`.

## Counts

0 CRITICAL, 0 HIGH, 1 MEDIUM (S-01), 4 LOW (S-02..S-05), 1 INFO (S-06).
