# v1 final code-health scan (scan half) — 2026-10-18

Branch `qa/v1-final` @ a302b3b1, compared with `c9e0e766` (start of this session's
changes: 102 commits, 167 files in `*.go`/`ui/src`/`tests/live`). The prior
`docs/security/V1_SCAN_2026-10-17.md` has only a qualitative tools table (no numbers),
so "before" below is measured by running the same tools on a c9e0e766 checkout.
Scan only: nothing was fixed.

## Metrics

| Tool | Before (c9e0e766) | After (HEAD) | Note |
|---|---|---|---|
| `make lint` (golangci-lint + wasm vet) | not run | **0 issues** | gate met |
| `staticcheck ./...` | 48 lines | 50 lines | +1 new (SA4000, H-F12); rest pre-existing (deprecated ecdsa X/Y/D in tests, ST1005 wstep, SA4023 main.go:151) |
| `deadcode ./cmd/...` | 75 | 77 | +`closeSharedPostgresPools` (test-only), +`(*Server).serveRST` already listed as method change; no new prod dead code besides the first |
| `gocyclo -over 25` (internal, cmd) | 100 | 100 | `wstep.(*Server).serveRST` 28 -> 32 |
| `gocognit -over 40` | 97 | 99 | new: `migration.(*Service).plan` 43, `wstep.(*Server).serveRST` 44 |
| top complexity | main 178 / cog 415 `registerCertificateHandlers` | unchanged | route-registration closures, long-standing |
| jscpd (internal + ui/src, non-test, >=20 lines) | not run | 65 clones, 2876 dup lines, **1.30%** | no baseline; low |
| `ui npm run lint` | - | 0 errors, 1 warning | unused eslint-disable in `public/mockServiceWorker.js` |
| knip (ui) | - | 15 unused files, 28 unused exports, 22 unused types, 2 duplicate exports | all unused files are shadcn primitives in `components/ui/` (kept deliberately?) |

## Findings

| ID | Sev | Location | Finding | Fix | Effort | Status |
|---|---|---|---|---|---|---|
| H-F1 | MEDIUM | internal/bootstrap/db_pool_config.go:84-150 | Shared Postgres pool cache is new package-level mutable state (`pgPoolsByService`, `pgUnsharedServices`, `openPostgresDBFn`) against the CLAUDE.md "no new global state" rule. The justification (45 constructors, no common receiver) is stated but not enforced; two hubs in one process (tests) share the cache. | Hang the cache off a `*poolRegistry` created in `main` and passed via the existing provider-state constructor; or record a D-xxx exception. | M | FIXED 30fe51a2 (by wave F1) | KEPT package-level, justification retained and tightened (45 constructors, no common receiver); exception recorded in the `db_pool_config.go` comment |
| H-F2 | MEDIUM | db_pool_config.go:~140 (`closeSharedPostgresPools`) | Comment says hub shutdown uses it; grep shows only tests call it (deadcode confirms). Production never closes shared pools, so the "shutdown" claim is stale and Postgres sees abrupt disconnects on SIGTERM. | Call it after `runServerCtx` returns (or from the drain hook) and fix the comment. | S | FIXED 30fe51a2 | FIXED: exported `CloseSharedPostgresPools`, deferred first in `main`; comment corrected |
| H-F3 | MEDIUM | db_pool_config.go `openSharedPostgresDB` | `db.Ping()` (no context/timeout) runs while holding `pgPoolsMu`; a hung Postgres blocks every store constructor for the driver timeout. | `PingContext` with 2-5 s timeout, or ping outside the lock. | S | FIXED 30fe51a2 | FIXED: ping/open outside `pgPoolsMu` with a 3 s `PingContext`; `openPool` ping bounded too |
| H-F4 | MEDIUM | internal/bootstrap/handlers_migration.go:233, handlers_policies.go:53 | `migrationPolicyEngine atomic.Pointer` is new global state, written as a side effect of `WithPolicyAdmin`; a second server/test in-process overwrites it. Reason given ("option order") is solvable. | Pass the engine into the migration handler after options are applied (resolve lazily from `ServerConfig`). | M | FIXED 9a0102be: `ServerConfig.policyEngine`, global removed, read lazily per plan |
| H-F5 | MEDIUM | internal/ca/policy_engine.go `AcceptedRSABits`, xcep/server.go `applyKeyPolicy` | N+1: per GetPolicies request, per offered template, up to 5 `Evaluate` calls and each does a DB `loadPoliciesFor`. Windows polls on every GPO refresh; ~10 templates = ~50 queries/poll. | Load policies once per request (or cache with policy-change invalidation) and evaluate in memory. | M | FIXED 071783e8 |
| H-F6 | MEDIUM | internal/migration/framework.go Apply (superseded loop) | Items are created/updated and the batch saved before superseded items are retired; a failure in `MarkItemDisabled` returns an error with the new batch already live, leaving two active items for one template. | Retire inside the same store transaction, or make the retire idempotent and retried on re-apply (no test covers this branch). | M | FIXED 8860b486 |
| H-F7 | MEDIUM | internal/migration/framework.go `plan` | cognitive 43 (new >40) after adding update/OID-match/floor branches. | Extract `classify(item, p)` and the OID-collision lookup. | M | FIXED 52e6df83 |
| H-F8 | MEDIUM | internal/wstep/server.go:295 `serveRST` | cyclomatic 28->32, cognitive 44 (new >40); enroll check + policy audit added inline. | Extract `authorizeTemplate` and `auditPolicyRefusal`. | S | FIXED 682693c4 |
| H-F9 | LOW | internal/wstep/server.go:456-480 | The doc comment of `templateExtension` is split: its second half now sits above the new `ProtocolRole` const block, and the function's own comment ends mid-sentence. Stale/misplaced. | Move the `ProtocolRole`/`RestrictedRole`/`EnrollPermitted` block above the comment. | S | FIXED 682693c4 |
| H-F10 | LOW | internal/bootstrap/handlers_estate.go:~440 | Audit "transition" detail is built with `fmt.Sprintf` and `%q`, which is Go quoting, not JSON (non-printable/unicode connector ids become `\x..`, invalid JSON). | `json.Marshal` a struct. | S | FIXED 90fb151a |
| H-F11 | LOW | internal/bootstrap/handlers_approval_inbox.go:46-56,194 | `templates ...TemplateProvider` variadic used as an optional parameter in two signatures (callers compile unchanged but the API hides a required dependency; `templates[0]` silently ignores extras). | Make it an explicit parameter; update the 2 call sites. | S | OPEN |
| H-F12 | LOW | internal/bootstrap/db_pool_share_test.go:51 | staticcheck SA4000 on `open(x) == open(x)` (intentional pointer-inequality check). New this session. | Assign both to variables and compare, so staticcheck is clean. | S | FIXED e55a0ffb |
| H-F13 | LOW | internal/bootstrap/approval_role_scope.go:42 | `GetTemplate` error is dropped (fail-closed, correct) but not logged; an unavailable template store silently hides approvals from approvers. | `logging.Warnf` once per template per request. | S | FIXED 90fb151a |
| H-F14 | LOW | internal/ca/policy_engine.go:345, migration/framework.go `raiseToFloor`, bootstrap/codesign_policy.go:53 | Three independent "is this an RSA algorithm / how many bits" parsers (`rsaAlgorithmBits`, `EqualFold("RSA")||HasPrefix("RSA-")`, `HasPrefix("RSA")`). | Export one `keystore`/`ca` helper and reuse. | S | FIXED 52e6df83 (ca.IsRSAAlgorithm; the bits parser stays, it returns a size) |
| H-F15 | LOW | internal/xcep/server.go | `max(t.MinKeySize, 2048)` repeated 2x plus the ladder floor 2048 in `AcceptedRSABits` and `rsaKeyLadder[0]`; default RSA minimum lives in 3 places. | One `defaultMinRSABits` const. | S | FIXED f4ecc48c: `defaultMinRSABits` in xcep (the ca ladder floor is noted beside it) |
| H-F16 | LOW | internal/xcep/server.go `auditServed` | `auditSeen` growth is bounded by authenticated principals and pruned, but pruning is an O(n) scan on every first/expired fetch under `auditMu`, and entries only expire when another principal arrives. Not a leak. | Optionally prune on a size threshold. Acceptable as is. | S | FIXED 5f5a1938 (same change as S-08) |
| H-F17 | LOW | internal/bootstrap/authz_custom_roles.go `isUniqueViolation` | Duplicate-key detection by substring of driver text; breaks on a driver message change (falls into "could not be saved", 500 instead of 409). Test covers sqlite only. | Check `*pgconn.PgError.Code == "23505"` / sqlite3 error codes via `errors.As`. | M | OPEN |
| H-F18 | LOW | internal/bootstrap/certificate_ca_provider.go `persistInventoryRevocation` | Raw `?`/`$n` duplicated SQL pair instead of the `rebind` helper used elsewhere (policy_engine). | Use the existing rebind helper. | S | OPEN |
| H-F19 | LOW | cmd/kryptkeeper/main.go:151 | SA4023 pre-existing: `NewPKCS11StoreFromEnv` never returns nil interface (stub), error branch is analyzable-dead. | Return `(keystore.Store, error)` honestly from the stub or drop the check. | S | FIXED ce7160e6: the stub returns the sentinel `ErrPKCS11NotCompiled` instead of a literal error |
| H-F20 | LOW | internal/wstep/server.go:516-591 | 9x ST1005 capitalised error strings (pre-existing). | Lower-case. | S | FIXED d5439e6f: the 9 wstep error strings are lower-case (SOAP fault text changes in case only) |
| H-F21 | LOW | tests/live/podman-dns.sh, run.sh files | `kk_wait_dns` returns 1 on timeout but all 6 call sites ignore it (prints NOTE, continues); the failure then shows up as a misleading http-01 error. Per-name `podman rm -f` is implemented 6 ways (`fx_rm` in ca-revoke/fixture.sh vs inline loops in acme, ca-rollover, policy-refusal, codesign-oidc, rollout); the `podman info ... sed aarch64/arm64` arch detection is pasted into 6 scripts. | Move `kk_rm`, `kk_goarch`, and a fatal `kk_wait_dns` into `podman-dns.sh` (rename `lib-podman.sh`). | M | FIXED 8895d5bd |
| H-F22 | LOW | tests/live/storm/results | 7 new run-result JSON files (+1023 lines) committed this session, 102 files tracked already. Churn in diffs and review. | Gitignore results, keep one `last-run.json`. | S | OPEN |
| H-F23 | LOW | ui/src/pages/CAs.tsx | 1856 lines (+183 this session); many `.catch(() => {})` after `mutateAsync` (11). The swallow is intentional (mutation `isError` is rendered) but undocumented and repeated. | Small `fireAndShow(mutation)` helper; split dialogs into files. | M | OPEN |
| H-F24 | LOW | ui (knip) | 15 unused shadcn primitives, 28 unused exports (e.g. `TakeoverDialog`, `BulkImportDialog` in Certificates.tsx, `Divider`), 22 unused types, duplicate default+named exports of `ErrorBoundary`, `PageHeader`. | Delete or mark as public API; drop duplicate exports. | M | OPEN |
| H-F25 | LOW | deadcode | Test-only exports (`RegisterHandlers`, `NewServer` in acme, `chatopsApprovalNotifier.drain`, `AllowLoopbackForTest`, ...) live in production files. Pre-existing except `closeSharedPostgresPools` (H-F2). | Move seams to `export_test.go`. | M | OPEN |

Reviewed with no defect found: drain hook goroutine (bounded by `drainHookTimeout`, idempotent
stops, exits when the hook returns; a hung hook leaks one goroutine for the rest of the shutdown
only), `runServerCtx` shutdown error now logged then intentionally not fatal, error text from
`persist` paths (custom role persist no longer leaks driver text, good), WSTEP policy-refusal
faults (name policy/rule only, no key material), `nextRowStamp` (monotonic, under lock),
`queryChangedCerts` cursor fix (rows closed on all paths, `rows.Err` checked).

## Package-level vars added this session

| Var | Justified? |
|---|---|
| `pgPoolsByService`, `pgPoolsMu` | Partly: real need, but violates the rule (H-F1) |
| `pgUnsharedServices` (map, read-only) | Yes, effectively a const |
| `openPostgresDBFn` | Test seam; OK but prefer a field (H-F1) |
| `migrationPolicyEngine` | No (H-F4) |
| `rsaKeyLadder`, `infraTemplateNames`, `restrictedEnrollRoles` | Yes, immutable tables (slices/maps never mutated) |
| `errAPIKeyMintingOff`, `errShuttingDown`, `errTemplateRevisionsUnsupported`, `errCustomRoleExists`, `errCustomRolePersist` | Yes, sentinel errors |

## Missing tests for new branches

- `Apply` superseded-item retire failure path (H-F6).
- `RenewCertificate` link stamp (`nextRowStamp` under `RLock`): covered only by the stale-row test, not by an error branch.
- `openSharedPostgresDB` Ping-fail reopen branch (backstop) has no test.
- `isUniqueViolation` Postgres/`23505` path (sqlite only).
- `resolveStateFilePath` is tested; `persistInventoryRevocation` zero-rows branch: confirm covered by `certificate_revoke_imported_test.go`.

## Flaky-test risk (tests added this session that use wall clock or timing)

| Test | Risk | Why |
|---|---|---|
| `server_shutdown_test.go` `ReadyzTurns503WhileStillServing` | MEDIUM | 600 ms drain, `Sleep(150ms)` then 4 HTTP calls with 2 s client timeout; on a starved CI box the drain can expire before the asserts, giving false failures. Widen drain to 2-3 s or use a channel from the hook. |
| `server_shutdown_test.go` other cases (500 ms hook, 200 ms shutdown timeout) | MEDIUM | Margins are 2-3x; same starvation issue. Others use 3-5 s ceilings which are safe. |
| `certificate_ha_refresh_test.go` `NoConnHeldWhileWaitingForProviderLock` | LOW | `Sleep(300ms)` assumes the scan reached `RLock`. If late the test passes vacuously (not a false failure); safe but weaker. Could poll a started flag. |
| `TestStaleRefreshRowDoesNotRevertTakeover` | LOW | 20 iterations of same-second writes; deterministic by construction (`nextRowStamp`) and was written because the race was ~1/500. |
| `xcep/keypolicy_test.go` | LOW | Uses an injected `now`; deterministic. |
| `bootstrap/anomaly_detect_test.go`, `certificate_revoke_imported_test.go`, `approver_role_scope_test.go`, `audit_action_prefix_test.go` | LOW | `time.Now()` only to build fixtures with hour-scale margins. |
| UI tests | LOW | `waitFor` with default 1 s timeout on mocked APIs; `login-alert`/`DialogScroll` use no timers. |

## Ranked fix backlog

1. H-F2 + H-F3 (S): close shared pools on shutdown, context-bound Ping; fix stale comment.
2. H-F6 (M): make superseded-item retire atomic/idempotent, add test.
3. H-F5 (M): remove the N+1 policy queries in XCEP GetPolicies.
4. H-F4 then H-F1 (M): remove `migrationPolicyEngine`; registry-ify the pool cache (or write the exception).
5. Shutdown/xcep timing tests: widen drain windows (MEDIUM flake).
6. H-F8, H-F7 (S/M): split `serveRST`, `plan`.
7. H-F9, H-F10, H-F12, H-F13, H-F14, H-F15 (all S): comment move, JSON audit detail, SA4000, log, RSA helper dedupe.
8. H-F21 (M): consolidate podman helpers; make DNS wait fatal.
9. H-F11, H-F17, H-F18, H-F19, H-F20 (S/M): API/driver-error hygiene and pre-existing lint.
10. H-F22-H-F25 (S/M): result files, CAs.tsx, knip, test seams.

Totals: 25 findings: 0 HIGH, 8 MEDIUM, 17 LOW. No security or crypto-path defects found in this scan.

## Fix status (wave F3, 2026-10-18)

| ID | Status |
|---|---|
| H-F10 | FIXED: `revertTransitionDetail` uses `encoding/json` (test added) |
| H-F11 | FIXED: `templates TemplateProvider` is an explicit parameter (nil allowed) on `RegisterApprovalInbox`, `registerApprovalInboxHandlers`, `collectInbox` |
| H-F12 | FIXED: SA4000 cleared in `db_pool_share_test.go` |
| H-F13 | FIXED: `GetTemplate` error logged via `logging.Warnf` (still fail-closed) |
| H-F14 | FIXED 52e6df83 (see the findings table) |
| H-F17 | FIXED: `isUniqueViolation` uses `pgconn.PgError` 23505 and sqlite extended codes 1555/2067 via `errors.As` (real-driver test) |
| H-F18 | FIXED: `persistInventoryRevocation` uses `rebindPostgres` |
| H-F21 | FIXED: `tests/live/lib/podman.sh` (`kk_rm`, `kk_goarch`, `kk_wait_dns`), `podman-dns.sh` removed, 36 scripts switched, DNS-wait timeouts now fail the step (`k8s/*` and `images`/`ad-ldap` keep their own arch fallbacks, different defaults) |
| H-F22 | FIXED: stamped storm results ignored, `results/last-run.json` tracked |
| H-F23, H-F24, H-F25 | OPEN: M-effort refactors (CAs.tsx split, knip pruning, test-seam moves) deferred; no behaviour risk |
| H-F9, H-F16 | F2 (wstep/xcep) |
| H-F15, H-F19, H-F20 | FIXED after the rescan: f4ecc48c, ce7160e6, d5439e6f |
