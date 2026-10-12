# Type Safety Findings, Kryptkeeper, 2026-10-09

Reviewer: type-safety-checker. Target: worktree code-review-2026-10-09 (= main 6062c62). Read-only pass.
Inputs: staticcheck.txt (2026.2.1), `go doc crypto/ecdsa` (go1.27.1 toolchain; module is Go 1.26), grep sweeps, 8 files read.

**Type Safety score: 7/10.** The UI is very clean (0 `as any`, 0 `@ts-ignore`, 0 non-null `!` in production code; TS 6.0 so `strict` is on by default). Go pending-action payloads are properly typed. The deductions are for the stringly-typed role/status model on the authorization path, a UI type layer that is mostly hand-written instead of generated, and the Go 1.26 deprecated ECDSA coordinate usage in the ACME JWK code.

| Severity | Count |
|---|---|
| CRITICAL | 0 |
| HIGH | 1 (TS-001) |
| MEDIUM | 4 (TS-002, 003, 004, 005) |
| LOW | 4 (TS-006 to 009) |
| INFO | 2 (strictness note, SA4023 triage) |

## Tooling status

- `tsc --noEmit` was NOT cleanly runnable: the worktree has no `node_modules`, and the main checkout's tsc fails with TS2688 (missing type libs). Pre-completion gate item is therefore partially met; no tsc error count is claimed.
- Strict mode: `ui/tsconfig.app.json` has no explicit `"strict"`. Under `typescript ~6.0.2` (package.json:54; installed 6.0.2) strict defaults to true. Verified empirically: a tsconfig without `strict` rejects `const a: string = null` (TS2322). So not a defect, see TS-009 for making it explicit.
- Go: `go vet`-level typing is fine; staticcheck results triaged below.

## Staticcheck triage

### SA1019: deprecated `ecdsa.PublicKey.X/Y` and `elliptic.Curve.IsOnCurve` (production sites: 2)

Replacement API verified with `go doc crypto/ecdsa`: `func ParseUncompressedPublicKey(curve elliptic.Curve, data []byte) (*PublicKey, error)` ("returns an error if the point is not in uncompressed form, is not on the curve, or is the point at infinity") and `func (pub *PublicKey) Bytes() ([]byte, error)`. Both exist from Go 1.25, so the module's Go 1.26 floor is satisfied.

| Site | What it does | Replacement |
|---|---|---|
| internal/acme/jws.go:214-215 (`JSONWebKey.publicKey`, EC branch) | Decodes JWK x/y into `big.Int`, builds `&ecdsa.PublicKey{Curve: P256, X: x, Y: y}`, then rejects off-curve points with `Curve.IsOnCurve`. This is the ACME account-key trust boundary (RFC 7518 6.2). | Left-pad x and y to exactly 32 bytes (reject `len > 32`), build `0x04 ‖ X ‖ Y`, call `ecdsa.ParseUncompressedPublicKey(elliptic.P256(), buf)`. It performs the on-curve and not-infinity check itself. |
| internal/acme/store_sqlite.go:242 (`publicKeyToJWK`, EC branch) | Serialises account key to JWK, manually zero-pads `key.X.Bytes()`/`Y.Bytes()` to 32 bytes (comment explains the RFC 7638 thumbprint reason). | `b, err := key.Bytes()` returns the fixed-length `0x04‖X‖Y` (65 bytes for P-256); use `b[1:33]` and `b[33:65]`. Deletes the manual padding and its failure mode. |

All other SA1019 hits for X/Y are in tests (jws_test.go:444, server_test.go:202-203, store_sqlite_test.go:349); they can move to `Bytes()` with the production change.

**On-curve check loss risk (flag, confidence 90):** the migration of jws.go:214-215 is the dangerous one. If a developer silences SA1019 by constructing the struct literal and simply deleting the `IsOnCurve` line (the linter-appeasing path), the invalid-curve check vanishes and `ecdsa.Verify` receives an attacker-chosen off-curve point (invalid-curve attack on a signature-verification path). `ParseUncompressedPublicKey` keeps the check, but ONLY if the code stops constructing the struct directly. Also keep an explicit test: a JWK with a valid-length but off-curve (x, y) must still return an error. Check that `jws_test.go` has such a case before migrating (not verified here).

### SA4023: cmd/kryptkeeper/main.go:134

The lead's premise (typed-nil interface) does not match the code, so correcting it:

- The always-true comparison is `err != nil`, not a nil check on the store. The default-build stub (internal/keystore/pkcs11_stub.go:13, `//go:build !pkcs11`) returns `(nil, fmt.Errorf(...))` unconditionally, so staticcheck (analysing default tags) proves `err != nil` always holds.
- Effect in the default binary: selecting `KRYPTKEEPER_KEY_BACKEND=pkcs11` always hits `log.Fatalf("pkcs11 keystore init: ...")` with the "rebuild with -tags pkcs11" message. That is the intended fail-closed behaviour. The unreachable branch is the success path (main.go:136 `log.Print("key backend: PKCS#11 (HSM)")` and fallthrough) in the no-tag build; in the `pkcs11` build (pkcs11.go:51, real implementation with env validation) it is live.
- No failure is masked. It is a false positive from build-tag stubs. Fix: run staticcheck with `-tags pkcs11` as well, or add a `//lint:ignore SA4023 build-tag stub` with that reason. Confidence 90. Severity INFO.
- The genuine typed-nil hazard is adjacent, see TS-006.

## Findings

### TS-001 HIGH, confidence 85: authorization roles are untyped string literals scattered across 12+ files
Module: internal/bootstrap. Only one role constant exists in the whole tree (`const RoleMCPAgent = "mcp-agent"`, mcp_role.go:24). Everything else is a bare literal compared against `AuthPrincipal.Role string`.
- Counts (production, lines): `"pki-admin"` 14, `"pki-operator"` 12, `"pki-auditor"` 2, `"pki-viewer"` 2. In tests: 95 / 84 / 8 / 48. Plus `"bootstrap"`, `"discovery-operator"`, `"notification-operator"`, `"protocol-operator"`, `"service-account"` literals.
- Sites: handlers_pending_actions.go:31 `case "pki-admin", "pki-operator":`; handlers_scep_challenges.go:43 `role != "pki-admin" && role != "pki-operator"`; authz_ops.go:12,30,39,48,57; authz_grant.go:35,74; authz_write_gate.go:158-159,187,197; authz_custom_roles.go:44-45,302,308; auth_identity.go:377 `strings.TrimSpace(role) == "pki-admin"`; auth_bootstrap.go:61; handlers_users.go:87; auth_config.go:146,166.
- Risk: a typo (`"pki-admn"`) compiles and silently turns a grant into a deny, or worse a deny-list comparison into a never-match (e.g. `role != "pki-admin" && ...` style gates fail open on a typo in the negated branch). There are also at least four parallel allowlists (canApproveActions, authz_ops.go switches, authz_write_gate.go map, authz_custom_roles.go builtin map plus switch) that must be edited in lockstep; drift between them is a permission-escalation or lockout bug. canApproveActions already hand-rolls the "deny RoleMCPAgent first" ordering because the allowlist is open-ended.
- Fix: `type Role string` with consts (`RoleAdmin`, `RoleOperator`, ...) in one file; `AuthPrincipal.Role Role`; a single `role.Can(Permission)` table replacing the switch statements; add a test that iterates all consts through every gate. Effort: M (mechanical, compiler-guided). Compounding note for synthesizer: same module as TS-002/TS-003.

### TS-002 MEDIUM, confidence 85: permission strings and role to permission map are untyped
Module: internal/bootstrap. authz_write_gate.go:158-159 maps role to `[]string{"certificate.read", "report.read", "audit.read"}` and authz_custom_roles.go validates custom-role permissions against string sets. A misspelt permission in a built-in role compiles and is simply never granted (fail-closed, but undetectable until a user complains), while a misspelt permission in a check is an always-false guard.
Fix: `type Permission string` with consts, one registry used by both the built-in table and the custom-role validator, plus a test that every permission checked in handlers exists in the registry. Effort: M.

### TS-003 MEDIUM, confidence 80: pending-action and certificate statuses are bare strings (63 literal comparisons)
Module: internal/bootstrap. handlers_pending_actions.go:121 `action.Status != "pending"`, :146 `Decide(..., "rejected", ...)`, :186 `"failed"`, :207 `"approved"`; only `statusExecuting` is a constant (mixed style within one handler). Elsewhere: `"active"` 58, `"revoked"` 23, `"expired"` 14, `"pending"` 15, `"approved"` 8, `"rejected"` 6 literal occurrences in non-test code; roughly 63 `Status/AuthType/Role == "..."` comparisons. The compare-and-set in `store.Decide` takes a free-form status string, so a typo yields a runtime state-machine error (or, for a store that does not validate, a row stuck outside every query filter).
Fix: `type PendingStatus string` with consts and a `Decide(ctx, id, to PendingStatus, ...)` signature; same for certificate lifecycle status. Effort: M.

### TS-004 MEDIUM, confidence 80: UI API types are mostly hand-written, not generated (contract drift risk)
Module: ui/src/lib. `src/generated/api-types.ts` (openapi-typescript, regenerated on prebuild/pretest) defines 39 schemas, but only 5 files import it (api.ts uses `components[...]` at 2 places, api.ts:41,743; Discovery.tsx:45, CryptoPosture.tsx:35, AlgorithmSunset.tsx, mocks/fixtures.ts). `src/lib/models.ts` hand-declares 52 exported types, several duplicating generated schemas: `ApprovalRequest` (models.ts:521; generated api-types.ts:3740), `UserRecord` (models.ts:80; api-types.ts:3374), `TemplateRecord` (models.ts:223; api-types.ts:3432), `ExecutiveSummary` (models.ts:392; api-types.ts:3686). Hand copy of `ApprovalStatus = "pending" | "approved" | "rejected"` (models.ts:519) omits the backend's `executing`/`failed` states used in handlers_pending_actions.go, which is exactly the API-contract trap in CLAUDE.md: the UI type says three states while the server emits five.
Also IssueWizard.tsx:20 hand-declares `PendingApprovalResponse` and api.ts:865 casts `(await res.json()) as { data?: { action_id?: string } }`.
Fix: derive duplicated types as `type ApprovalRequest = components["schemas"]["ApprovalRequest"]` in models.ts (single re-export point, no call-site churn); add a lint/CI check that fails on a models.ts type whose name collides with a generated schema. Effort: M.

### TS-005 MEDIUM, confidence 75: unchecked casts on response JSON in the UI client
Module: ui/src/lib/api.ts. `fetchJSON<T>` returns `body` from `res.json()` (api.ts:238-338 area) typed as `T` with no runtime validation; api.ts:865 uses a bare `as`. Server shape changes surface as `undefined` property reads, not type errors. Acceptable for an internal API with generated types, but combined with TS-004's hand-written `T`s there is no point where the contract is checked.
Fix: finish TS-004; for the few security-relevant responses (authz, pending-action decisions) add a type-guard like the existing `isPendingApproval` in IssueWizard.tsx:30. Effort: S to M.

### TS-006 LOW, confidence 80: latent typed-nil assignment into `keystore.Store`
Module: cmd/kryptkeeper. main.go:139 `keys, err = keystore.NewVaultStoreFromEnv()` where the function returns `(*VaultStore, error)` (vault.go:59) and `keys` is `keystore.Store` (main.go:106). On error `keys` becomes a non-nil interface holding a nil `*VaultStore`. Today the next statement is `log.Fatalf`, so it is benign; if that branch ever degrades to a warning/fallback, `keys == nil` checks (e.g. downstream `if keys != nil`) pass and methods get called on a nil receiver. Fix: `vs, err := ...; if err != nil {fatal}; keys = vs`, or return `Store` from the constructor like the PKCS11 one. Effort: XS.
Not verified: the ~35 other `New*FromEnv() <Interface>` constructors (bootstrap/*_provider.go, e.g. notification_provider.go:92, audit_provider.go:79) were not read for concrete-nil returns; the same pattern applies if any return a typed pointer var.

### TS-007 LOW, confidence 85: pending-action params are opaque until execution; error text stale
Module: internal/bootstrap. handlers_pending_actions.go:80-84 validates only `ActionType`; `Params json.RawMessage` is stored verbatim and first parsed in executePendingAction (pending_action_exec.go:37-130) where `json.Unmarshal` into typed structs (`bulkRevokeParams{CAID, ReasonCode int, ReasonText}`) tolerates unknown fields and any int `reason_code`. Positive: params ARE decoded into typed structs, not `map[string]any`, and results use `map[string]any` only for output. Weaknesses: (a) an approver can approve a malformed proposal that then fails at execution; (b) no RFC 5280 reason-code range check at proposal time; (c) the 400 message says "(revoke, bulk_revoke)" (line 81) while `validActionType` (pending_action_exec.go:193) accepts five types: stale user-facing text.
Fix: per-action-type `validateParams` called at POST (use `DisallowUnknownFields`, range-check reason code), fix the message to be generated from the same list. Effort: S.

### TS-008 LOW, confidence 80: dead-ends in ad-hoc `map[string]any` plumbing
Module: internal/bootstrap. 78 `map[string]any` occurrences in non-test code. Security-path uses reviewed (pending-action results, pending_action_exec.go:50,89,103,117) are output-only and safe. Type-assertion hotspots with `.(string|float64|map[string]any)` are JWT/OIDC claim parsing: auth_jwks.go (6), auth_hs256.go (6), auth_oidc_login.go (2). These use comma-ok form where sampled (grep found no bare single-value assertions in non-test Go), which is correct; the residual risk is claim-type confusion (e.g. `aud` as string vs array, numeric `exp` as float64), which should be centralised in one typed claims struct instead of per-file assertions. Effort: M. Confidence capped at 80: JWT files not read in depth.

### TS-009 LOW, confidence 90: strictness is implicit in tsconfig; one `any` remains
Module: ui. (a) `tsconfig.app.json` relies on TS 6.0's default `strict: true`; a toolchain pin change or a copied config would silently drop it. Add `"strict": true` explicitly (fix: 1 line, XS). (b) src/mocks/handlers.ts:5-6 `const ok = (data: any) => ...` with an eslint-disable for `no-explicit-any`; use `unknown` (HttpResponse.json accepts it) or a generic. (c) Test-only: 169 `as unknown as` and 6 `@ts-expect-error` in test files, plus src/test/setup.ts:83; acceptable for mocks, noted for inventory. Four `eslint-disable-line react-hooks/exhaustive-deps` (Alerts.tsx:56, CAs.tsx:208, Discovery.tsx:113, Certificates.tsx:545) are stale-closure risks, not type holes, flagged for the pattern checker.

## Inventory counts (for the synthesizer)

| Check | Go | UI (prod) | UI (test) |
|---|---|---|---|
| `any` / `interface{}` escapes | 78 `map[string]any` uses; assertions comma-ok where sampled | 1 (`mocks/handlers.ts:6`) | 0 |
| `as any` | n/a | 0 | 0 |
| `as unknown as` | n/a | 0 (1 in test/setup.ts) | 169 |
| `@ts-ignore` / `@ts-expect-error` | n/a | 0 | 0 / 6 |
| Non-null `!` | n/a | 0 | not counted |
| Deprecated crypto API (SA1019) | 2 prod sites + 4 test files | n/a | n/a |
| Stringly-typed roles | 30 prod literal lines, 235 test lines | n/a | n/a |

## Summary table

| ID | Sev | Conf | Module | Item |
|---|---|---|---|---|
| TS-001 | HIGH | 85 | internal/bootstrap | Role literals everywhere, 1 const |
| TS-002 | MEDIUM | 85 | internal/bootstrap | Permission strings untyped |
| TS-003 | MEDIUM | 80 | internal/bootstrap | Status strings untyped, `Decide` takes string |
| TS-004 | MEDIUM | 80 | ui/src/lib | models.ts hand-written vs generated; ApprovalStatus drift |
| TS-005 | MEDIUM | 75 | ui/src/lib | Unvalidated `res.json()` casts |
| TS-006 | LOW | 80 | cmd/kryptkeeper | Typed-nil `*VaultStore` into `Store` |
| TS-007 | LOW | 85 | internal/bootstrap | Pending params unvalidated until execute; stale error text |
| TS-008 | LOW | 80 | internal/bootstrap | Claim assertions scattered |
| TS-009 | LOW | 90 | ui | Implicit strict; one `any` |
| SA1019 | MEDIUM (if on-curve check dropped) | 90 | internal/acme | Migrate to ParseUncompressedPublicKey / Bytes, keep off-curve test |
| SA4023 | INFO | 90 | cmd/kryptkeeper | Build-tag stub false positive, not typed-nil |

(SA1019 is counted under MEDIUM in the headline table as a fifth MEDIUM-class item if it regresses; as written today it is a deprecation, severity LOW. Headline counts above list TS-IDs only.)

## Not verified / limits
- tsc not run (see Tooling status); no UI error counts claimed.
- JWT/OIDC files, the 35 other `FromEnv` constructors and jws_test.go off-curve coverage were grepped or inferred, not read.
