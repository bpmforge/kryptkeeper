# Code Health Review: Kryptkeeper v0.9.0-rc.1 candidate (d74edf3), 2026-10-10

Scope: (1) verify the 13 release-blocking items of `FIX_BACKLOG_code-health_2026-10-09.md` in code at d74edf3;
(2) review only code added since the review merge a9288d2 (`git diff a9288d2 d74edf3`: 71 files, +4154/-731, 36 non-test Go files, 6 UI source files).
Read-only on code. `go build ./...` clean. The pinning tests named below were run and pass (`cmd/kryptkeeper`, `clientip`, `egress`, `ratelimit`, `acme`, `ca` in full; `bootstrap` filtered to the pinning tests). The full suite was not re-run here.
`authz_grant.go`, `auth_password.go`, `auth_login_state.go`, `auth_saml_guard.go` are unchanged since a9288d2 and were not re-reviewed.

## Verdict: PASS

All 13 items are fixed in code and pinned by tests, with two residual sub-items that I judge not release-blocking (FB-02 `MkdirAll`, FB-04 call-site propagation). No new HIGH or CRITICAL code-health finding in the added code: 0 HIGH, 4 MEDIUM, 9 LOW.

Blockers: none. **PASS assumes the owner accepts two residuals** (this is a recommendation, not an existing decision): (a) FB-04: the counter plus detached 5s context are treated as sufficient for the issue, revoke and key-op sites, which still do not return an error to the caller (the backlog's "minimum for v0.9" named all four site classes; only approve consumes it); (b) FB-02: the unchecked `MkdirAll` at `main.go:120`. If the owner reads the gate strictly ("all items verified fixed"), the verdict is CONDITIONAL on those two. Separately, N-01 (renewal retry state resets silently on the default file audit provider) is the finding most worth a pre-tag fix. It is MEDIUM, not HIGH, because it needs an existing-but-unreadable audit file (a missing file on first boot correctly reads as zero history) and issuance stays capped at one successor per certificate by the `SuccessorFP` guard; the impact is hammering of a broken target and an inert retry feature, not uncontrolled issuance.

## 1. FB verification (d74edf3)

| ID | Status | Evidence in code | Pinning test(s) |
|---|---|---|---|
| FB-01 policy gate | VERIFIED | `cmd/kryptkeeper/startup_ca.go:32` `attachPolicyEngine` returns an error; `main.go:186` `log.Fatalf`; escape hatch `KRYPTKEEPER_ALLOW_NO_POLICY` logs `WARNING ... DISABLED` | `TestAttachPolicyEngineFailureIsFatalUnlessAllowed` |
| FB-02 second root | PARTIAL | `startup_ca.go:56` `resolveDefaultCA` checks the `ListCAs` error before the empty test; flag parsed by `envTrue` (case-insensitive, accepts `1`). **Sub-item not done:** `main.go:120` `os.MkdirAll(keystoreDir, 0o700)` still ignores its error | `TestResolveDefaultCAListErrorDoesNotMintRoot`, `TestResolveDefaultCA` |
| FB-03 deprovision fail-open | VERIFIED | `auth.go:~245-257` fails closed (`errUserStoreUnavailable`) for `AuthType=="local"` sessions other than the env admin; bootstrap token and API keys exempt (`auth_identity.go:206`); `Refresh` fails closed and restores the single-use token (`auth_identity.go:~263`); `/authz-check` returns 503 (`handlers_auth.go:231`); audit `authz.userstore_error`, throttled to one per 30s. External jwt/oidc bearer tokens still fail open on store error, deliberately and with a test | `TestAuthMiddleware_UserStoreErrorFailsClosedForSessionPrincipals`, `...DoesNotAffectBootstrapAPIKeyOrEnvAdmin`, `TestRefresh_UserStoreErrorFailsClosedAndKeepsToken`, `TestAuthzCheck_UserStoreErrorReturns503`, `TestAuthMiddleware_BearerTokensFailOpenOnStoreErrorButHonourDeactivation` |
| FB-04 audit append | PARTIAL (accepted) | `audit_events.go:69` `context.WithTimeout(context.WithoutCancel(r.Context()), 5s)`; counter `kryptkeeper_audit_append_failures_total` (`metrics/vars.go`); `emitAuditEventDetailErr` returns the error. **Only the approve path consumes it**; issue/revoke/key-op sites remain log-only. The code documents this limitation (`audit_events.go:23-28`) and the backlog defers the full design to v0.10 | `TestAuditAppendSurvivesCancelledRequestContext`, `TestAuditAppendFailureIncrementsMetric` |
| FB-05 approve then Decide fails | VERIFIED | `handlers_pending_actions.go:218` `decideDetached` (detached ctx, one retry), audit `action.approve` outcome `executed`, generic 500 text; the reject path no longer echoes SQL text. Outcome string is `executed`, not the backlog's `executed_unrecorded` (immaterial) | `TestApproveDecideFailureAfterExecutionIsAuditedAndGeneric`, `TestRejectDecideFailureDoesNotLeakError` |
| FB-06 SIEM wired | VERIFIED | `main.go:246-247` one router; `WithSIEMForwarding` wraps the only `NewAuditProviderFromEnv()` call site; `audit_events.go:86` forwards after a durable append through a bounded queue (1024) with a drop counter and an egress-guarded client; the same router is handed to Status/Test (`WithSIEMRouter`). `deadcode` no longer lists `Emit`/`EmitFromAuditEntry` | `TestAuditEventReachesSIEMWebhook`, `TestSIEMNotForwardedWhenAuditAppendFails`, `TestSIEMFullQueueDoesNotBlock`, `TestSIEMWebhookUsesEgressGuard`, `TestWithSIEMForwardingDoesNotDoubleWrap` |
| FB-07 pinned-connector renewal | VERIFIED | `renewal_executor.go:185` `WithEnvConnectorRegistry` used by all four executor constructors (scheduler via `NewRenewalExecutorFromEnv`, manual execute, rollout); `renewMaterial` `:554-559` fails closed on registry error or nil; registry rebuilt per renewal | `TestRenewMaterialConnectorPinnedWithoutRegistryFailsClosed`, `TestRenewMaterialRegistryFuncErrorAndUnknownConnectorFailClosed`, `TestRenewMaterialRegistryFuncRebuiltPerRenewal`, `TestRenewMaterialUnpinnedStillUsesHubCA`, `TestRenewalExecuteHandlerPinnedUnknownConnectorFailsClosed`, `TestRenewalExecuteHandlerPinnedConnectorRoutesUpstream` |
| FB-09 exceptions claims | VERIFIED (docs/UI) | `CryptoPosture.tsx:215` and `Discovery.tsx:50` show only "Total findings"; `docs/openapi.yaml:581` and `docs/ROADMAP.md:30` state suppressed is always 0 until v0.10; store comment `finding_exception_store.go:89`. The word "suppressed" stays in openapi as an explicitly reserved field rather than being dropped | none (text only; no UI test asserts the removal) |
| FB-10 client IP | VERIFIED | one `internal/clientip` (rightmost-untrusted XFF, then X-Real-IP, a malformed hop stops the walk); `ratelimit.go:36`, `auth_rate_limit.go:152`, `auth_oidc_login.go:90`, `http_security.go:23`, `audit_events.go:136` all use it; duplicate funcs and the stale comment are gone; `env.example:30-37` documents `APP_TRUSTED_PROXY_CIDRS` | `clientip` `TestResolve`/`TestPeerTrusted`/`TestFromEnv`, `TestClientIP_TrustedProxyUsesRightmostUntrustedXFF`, `TestMiddleware_TrustedProxyIgnoresSpoofedLeftmostXFF`, `TestExtractSourceIP_TrustedProxyAware` |
| FB-11 http-01 dial list | VERIFIED | `acme/http01.go:30` `egress.Policy{AllowPrivate:true}.DialControl()`; `refuseInternalAddr` deleted | `egress.TestCheckIPTable` (rows `0.0.0.0`, `64:ff9b::a9fe:a9fe`, `64:ff9b::7f00:1`), acme fg1 dial table incl. `[64:ff9b::7f00:1]:80` |
| FB-12 evidence honesty | VERIFIED | `handlers_reports.go:1124` `tallyExpiry` with an `unknown` bucket; `soc2LifecycleControl` cannot pass with unknown expiry; injected `now` (`computeComplianceEvidenceAt`); a `ListCAs` error is 503 in the evidence handler (`:378`) and executive summary, and an error in the evidence pack (`handlers_evidence.go:27`) | `TestSOC2LifecycleControl_UnknownExpiryIsNotPass`, `TestTallyExpiry_ParsesOncePerCertAndBuckets`, `TestRenderEvidencePack_ListCAsErrorFailsInsteadOfOmittingCAs`, `TestExecutiveSummaryHandler_ListCAsErrorIs503`, `TestComplianceEvidenceHandler_ListCAsErrorIs503` |
| FB-13 publicKeyBits | VERIFIED | `ca/key_strength.go:50` `PublicKeyBits` (RSA `N.BitLen`, EC curve size, Ed25519 256); `certificate_ca_provider.go:1140` delegates; stored zero rows are recomputed on load; the stale acme comment is replaced by a real value (`acme/server.go:915`). Score and flags are now one ladder (`riskFlagWeights`) | `TestPublicKeyBits`, `TestRiskScoreAndFlagsAgree`, `TestRiskFlags200DayRuleUsesInjectedNow` |
| FB-14 pre-auth bodies | VERIFIED | `request_body.go` `decodeJSONBody`/`decodeJSONBodyOrReject` (413 vs 400); used by login, refresh, API-key create, agent register/inventory/result, SCIM (all five body reads capped, including `io.ReadAll` after `capBody`); agent handlers use envelope helpers; register refusal text is logged, not returned (`handlers_agents.go:725`) | `TestPreAuthBodies_OversizeRejectedWith413`, `TestAgentInventory_LargePushWithinCapAccepted`, `TestAgentErrors_DoNotEchoInternalText` |

Summary: 11 VERIFIED, 2 PARTIAL (FB-02 sub-item, FB-04 propagation), 0 NOT FIXED.

## 2. New findings in code added since a9288d2

Severity scale as in the 2026-10-09 review. Confidence is my confidence that the defect exists as described.

### MEDIUM

**N-01 Renewal retry/backoff state silently resets when the audit store cannot be read or written** (conf 85)
`internal/bootstrap/renewal_scheduler.go:669-693` (`installState`), `:556` (`emitRenewalAudit`), `internal/bootstrap/audit_file_provider.go:46-56`.
The new bounded-retry design keeps attempt state only in the audit log, and two paths make that state fail open:
(1) the default `file` audit provider turns a read or JSON error into an empty, nil-error result (`log.Printf("audit file fallback: unreadable %q: %v", ...)` then `return AuditListResult{...}, nil`), so `installState` sees zero failures and the new `serr != nil` fail-closed branch in `runScan` never fires;
(2) `emitRenewalAudit` only logs `renewal scheduler: audit append failed`, so a failure whose row did not persist is never counted.
Either way `failures` reads 0 and `renewalInstallMaxAttempts` / `installBackoff` are bypassed. Consequences, traced through the `switch` in `runScan` (`cert.SuccessorFP != nil && st.failures == 0` skips): (a) failures before issuance (connector unreachable, key generation error; no successor is set) retry on every tick with no backoff, which is a regression from the old code that recorded a cooldown on every attempt (`tryAutoRenew` no longer touches `cooldownStore`); (b) a failure after issuance leaves a successor, so the cert is then skipped as "renewed by someone else": the install is attempted once and silently abandoned, `PendingInstalls` stays 0 and the retry feature is inert (the owner still gets the normal expiry reminder). There is no repeated issuance: the successor guard caps it at one certificate per original.
Fix: record the attempt before executing, or keep an in-memory per-fingerprint floor beside the audit-derived state; make the file provider return its read error from `ListEntries`; treat a failed append of a failure row as "back off one interval".

**N-02 An unparseable failure timestamp disables backoff** (conf 80)
`renewal_scheduler.go:688` `st.lastFailure, _ = time.Parse(time.RFC3339, e.Timestamp)`.
On a parse error `lastFailure` stays zero, so `now.Before(st.lastFailure.Add(backoff))` at `:760` is false and the retry runs immediately on every tick. The DB and file providers emit RFC3339 today; the error is swallowed regardless.
Fix: on a parse error set `lastFailure = now` (back off) and log once.

**N-03 `clientip.FromEnv()` re-parses `APP_TRUSTED_PROXY_CIDRS` on every call, on hot paths** (conf 90)
`audit_events.go:136` (once per audited request), `auth_rate_limit.go:152` (every login/refresh/OIDC bucket), `auth_oidc_login.go:90`, `http_security.go:23` (every response that checks secure-cookie status). `Resolver` is documented immutable and shareable, but each call does `os.Getenv`, `strings.Split` and a `netip.ParsePrefix` per CIDR and allocates. It also lets the limiter and the audit row disagree if the env changes mid-process, which the package doc ("two limiters can never disagree") says it prevents. `ratelimit.go:36` does it correctly (built once in the constructor).
Fix: `var defaultResolver = sync.OnceValue(FromEnv)` in the package, or inject a `*Resolver` through `Authenticator`; tests that set the env use `New`.

**N-04 SIEM forwards 7 audit actions only, and the allowlist is rebuilt on every audit event** (conf 90)
`siem_integration.go:528` `table := map[string]mapping{...}` inside `mapAuditActionToSIEM` lists `certificate.issue/revoke`, `ca.create/suspend/activate`, `auth.login`, `auth.login_failed`. Not forwarded: `action.approve`/`action.reject`, `authz.userstore_error`, key operations, role and user changes, the new `certificate.renew_execute_failed`/`..._gave_up` rows, `integration.siem.*`. The table predates the review, but FB-06 now makes it the only thing a SIEM ever sees, and the Integrations page implies audit forwarding. The map is allocated per audit event (about 800 call sites).
Fix: package-level `var siemActionMap`, and either forward every action with a default severity or list the forwarded set in the SIEM docs and openapi.

### LOW

**N-05 `autoRenewOutcome.attempted` is written but never read** (conf 95). `renewal_scheduler.go:733` (set at `:770`, `:798`). Dead field; delete it.

**N-06 `emitAuditEventDetail` contains a no-op `if`** (conf 95). `audit_events.go:33-36`: `if err := ...; err != nil { return // already logged and counted }` at the end of the function. Use `_ = emitAuditEventDetailErr(...)` with the comment.

**N-07 `os.MkdirAll` error still ignored** (conf 95). `cmd/kryptkeeper/main.go:120`. Part of FB-02; `if err := os.MkdirAll(...); err != nil { log.Fatalf(...) }`.

**N-08 Fourth copy of env-bool parsing** (conf 85). `cmd/kryptkeeper/startup_ca.go:23` `envTrue` duplicates `bootstrap.envBool` (`env_helpers.go:42`) because that one is unexported; its comment admits the mirroring. Counts toward HB-06; export one helper instead of adding copies.

**N-09 Stringly-typed security branches added** (conf 80). `auth_identity.go:206,216` compare `pd.AuthType` to `"bootstrap"`, `"api-key"`, `"local"` (the fail-closed branch depends on one literal staying `"local"`); `ui/src/lib/auth.tsx:33-47` adds an 11-role literal allowlist (`canReadKeyInventory`) mirroring Go's `fixedRolePermissions`; `riskFlagWeights` (`certificate_ca_provider.go:~1347`) keys scoring by flag-name strings, so a flag added to `computeRiskFlags` without a weight scores 0 silently (`TestRiskScoreAndFlagsAgree` samples three certificates). All extend LC-01. Fix: `type AuthType string` consts; a test that iterates every flag `computeRiskFlags` can emit against `riskFlagWeights`.

**N-10 `WithConnectorRegistry` has no production caller left; every executor opens its own connector store** (conf 80). `renewal_executor.go:133` is used only by tests. `WithEnvConnectorRegistry` (`:185`) calls `newConnectorStoreFromEnv()` once per executor (scheduler, manual execute, rollout), each with its own DB handle that is never closed. If the DB is briefly down at first use, `store` stays nil for the executor's life (`sync.Once`), so pinned certificates fail closed until restart: safe but unrecoverable. `renewMaterial` now takes 8 parameters (`:550`). Fix: build one `ConnectorStore` in main and share it; resolve lazily with retry instead of `sync.Once`.

**N-11 SIEM queue goroutine has no shutdown flush** (conf 75). `siem_integration.go:212-225` `drain()` ranges over a channel that is never closed; events queued at SIGTERM are lost, and a `queueSize` test seam sits on the production struct (`:69`). Acceptable for rc.1 because the audit log is the record of truth; state it in the SIEM docs.

**N-12 `extractSourceIP` fallback returns `r.RemoteAddr` with the port** (conf 80). `audit_events.go:136-139`. The old code split host and port; `ClientIP` returns "" only when `RemoteAddr` is unparseable, so this is rare, but the audit `SourceIP` then holds `host:port` or garbage. Return "" instead.

**N-13 `include_chain=true` silently returns the bare leaf with 200 when the chain lookup fails** (conf 80). `certificate_ca_provider.go:919` `appendIntermediatesPEM` logs and returns `leafPEM`; the caller cannot tell a leaf-only answer from a root-issued leaf. A client building a fullchain file gets a chain that fails verification later. Fix: return an error (502/503) or add a response header such as `X-Chain-Incomplete: true`.

### Checked and clean (no finding)
- `request_body.go`: one decode helper, one 413 path, no raw error text; consistent with surrounding handlers (SCIM uses `writeSCIMBodyError`).
- Fail-closed auth work: no error text returned to clients (503 "auth unavailable"), audit row throttled, `Refresh` restores the single-use token only on store error. `Authenticator.auditProvider` is written at wiring time without a lock (documented); a race only if mux registration ever ran after serving started.
- `DownloadCertificate` `include_chain`: `bytes.Clone` avoids mutating shared PEM, root excluded and documented (chain-lookup degradation is N-13); test `TestCACertificateProviderDownloadIncludeChain`.
- `managed_targets.verify_host_port`: validated on create and update, migration 000071 present, `ALTER` guards added to both `EnsureSchema` lists.
- `CloudKeys.tsx`: typed from generated `paths`, 403 handled through `status` on the thrown error, error strings are the server's sanitised form, no `any`, no non-null assertions, `aria-sort` headers; route at `App.tsx:321`; `cloud-keys.test.tsx` and `nav.test.ts` added or extended.
- Silent skips of unparseable `ValidUntil` remain in the executive-summary buckets and the expiry forecast (`handlers_reports.go:515`, `:768`). Same class as FB-12 but outside its cited scope and unchanged by this diff; carry into Wave B.

## 3. Tool delta (whole tree: baseline `docs/work/code-reviewer/health-2026-10-09/` vs RC `scratchpad/rc1/health/`)

| Tool | Baseline | RC | Delta |
|---|---|---|---|
| gocyclo >15 | 129 | 129 | `main` 133 to 129; `computeComplianceEvidence` 45 split into `computeComplianceEvidenceAt` 34 plus helpers; `computeRiskScore` (33) gone because it now sums flags; newly over threshold: `loadCertsFromDB` 17 |
| gocognit >20 | 121 | 120 | `main` 304 to 288; compliance 83 to 67; `computeRiskScore` 35 gone; **`runScan` 34 to 59** (retry/backoff branching inline; cyclo 19 to 25) |
| staticcheck | 74 | 75 | +1: unused field `stubAuditProvider` in `auth_failclosed_test.go` (U1000, test only); SA1019/SA4023 set unchanged |
| deadcode (with tests) | 43 | 39 | removed: `BuildConnectorRegistry`, `SIEMRouter.Emit`, `EmitFromAuditEntry`, `mapAuditActionToSIEM` (the FB-06/07 wiring); none added |
| gofmt | 4 files | 4 files | same four files, none touched by this diff |
| jscpd (Go) | report only | report only | no new clone block attributable to the diff beyond N-08 and the repeated `pinnedRegistry` / `generateRenewalKeyAndCSR` / `renewMaterial` triple at three sites in `renewal_executor.go` (three-fold before the diff too) |

Changed-file scan (`gocyclo -over 15`, `gocognit -over 20` restricted to the 36 changed non-test files): about 33 functions over each threshold, all pre-existing except `runScan` (worse) and `loadCertsFromDB` (crossed). Nothing new above 35 cyclomatic. `runScan` is the one function this diff made materially harder to reason about; extracting the per-candidate auto-renew `switch` (`:350-385`) would bring it under 40 cognitive and give N-01 a testable seam.

## 4. Remaining Wave B/C items

None of HB-01..HB-09 or LC-01..LC-10 became HIGH. HB-06 (bool env idioms) gained one copy (N-08); LC-01 (typed roles) gained N-09; HB-01 (raw errors to clients) still applies to the execute-failure text in `handlers_pending_actions.go:212,215` (`"action failed: "+execErr.Error()`, approvers only).

## 5. Recommended before tagging (all effort S, none gating)
1. N-01 and N-02: record the attempt before executing, surface file-provider read errors, make a timestamp parse error back off.
2. N-07: check the `MkdirAll` error, which closes FB-02.
3. N-03: build the `clientip.Resolver` once.
