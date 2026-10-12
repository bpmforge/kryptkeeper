# Code Health Re-Review: Kryptkeeper v0.9.0-rc.2 candidate (6200a0d), 2026-10-10

Scope: (1) re-check the RC1 open items (FB-02, FB-04, N-01..N-13); (2) review the delta `git diff d74edf3 6200a0d`
(`*.go` and `ui/src/**/*.ts(x)`, generated excluded): 71 non-test, non-generated source files, 67 commits, plus the matching tests;
(3) whole-tree tool delta against the RC1 baseline. Read-only on code. `go build ./...` clean. Run here and passing:
`internal/clientip`, `internal/ratelimit`, `cmd/kryptkeeper` in full; `internal/bootstrap` filtered to the pinning tests named below
(`InstallState|SIEM|ResolveAuditProvider|Oversize|PreAuthBodies|StampVerif|Reissue|Egress|UnknownExpiry|AuditAppend`).
The full suite was not re-run here.

## Verdict: PASS

Gate conditions: RC1 partials FB-02 and FB-04 are resolved/accepted; N-01..N-04 are fixed in code with tests; no new HIGH or CRITICAL
in code changed since RC1. New findings: **0 HIGH, 3 MEDIUM, 12 LOW**. None blocks the tag. The MEDIUMs are maintainability and
type-safety debt that grew in the delta (see section 3); fix or schedule them before 1.0, not before rc.2.

## 1. RC1 items

| ID | Status | Evidence (code) | Test |
|---|---|---|---|
| FB-02 `MkdirAll` | FIXED | `cmd/kryptkeeper/main.go:120` `if err := os.MkdirAll(...); err != nil { log.Fatalf(...) }` | none (inline in `main`; no seam). LOW gap |
| FB-04 audit append | ACCEPTED, with the mitigations the gate asked for | Store fails closed at startup: `main.go:~254` `ResolveAuditProvider` error is `log.Fatalf("refusing to start: audit store unavailable")`; `audit_provider.go:85`. Failures counted at the single choke point `siemAuditProvider.AppendEntry` (`audit_events.go:93-97`, `metrics.AuditAppendFailures`), so scheduler, protocol and ceremony writers are counted too, not only handlers. Non-approval sites stay log-plus-counter by design; the limitation is stated at `audit_events.go:24-31` | `TestResolveAuditProviderFailsClosedOnUnopenableStore`, `TestAuditAppendFailureIncrementsMetric`, `TestAuditHandlerFailsClosedWhenProviderUnavailable` |
| N-01 retry state resets | FIXED (read path), residual LOW | File provider is now JSONL and `ListEntries` returns the read error (`audit_file_provider.go` ~L238 "Unreadable is not the same as empty"); `installState` error reaches the `serr != nil` fail-closed branch. Residual: `emitRenewalAudit` (`renewal_scheduler.go:563`) still only logs a failed append, so a lost failure row is invisible to backoff. It is now counted by the metric, and an append failure implies the store is broken, which the next `installState` read usually surfaces | `TestInstallStateSurfacesUnreadableHistory`, `TestInstallStateOverFileProviderReportsReadError` |
| N-02 timestamp parse | FIXED | `renewal_scheduler.go:~761` parse error logs and sets `lastFailure = time.Now().UTC()` (backs off). Nit: uses wall clock, not the injected `now` (RC2-L7) | `TestInstallStateUnparseableTimestampStillBacksOff` |
| N-03 `clientip.FromEnv` per call | FIXED (different design than proposed) | `clientip.go` `envResolver atomic.Pointer[envParse]` memoises per distinct env value; the comment explains why not injection. Still picks up env changes, so tests are unaffected | `TestFromEnv_ReusesParseUntilEnvChanges` |
| N-04 SIEM 7 actions, per-event map | FIXED | `siem_integration.go:528` package-level `siemKnownActions`; every action forwarded under its own name; optional `KRYPTKEEPER_SIEM_ACTIONS` exact/`prefix.*` allowlist; documented in `env.example:390` and CHANGELOG. Package header comment is still stale (RC2-L1) | `TestSIEMForwardsEveryAuditActionByDefault`, `TestSIEMActionAllowlist` |
| N-05 `attempted` dead field | OPEN | `renewal_scheduler.go:813` still written at `:844,:868`, never read | none |
| N-06 no-op `if` | OPEN | `audit_events.go:33-35` unchanged | none |
| N-07 `MkdirAll` | FIXED | same as FB-02 | none |
| N-08 4th env-bool copy | OPEN | `startup_ca.go:23` `envTrue` still mirrors `bootstrap.envBool`/`envBoolDefault` (`env_helpers.go:42,47`); 9 more inline `== "true"` comparisons remain in non-test code | none |
| N-09 stringly-typed auth | OPEN, worsened | Auth-kind literals `"bootstrap"`, `"api-key"`, `"local"` now also in `egressStamp` (`egress_stamp.go:30-38`), `canonicalHuman`, `grantBoundTo`, `isBootstrapHuman`; 15 comparison/literal sites; see RC2-M2 | none |
| N-10 `WithConnectorRegistry` / store lifecycle | OPEN | still test-only caller; `renewal_executor.go:189-192` `sync.Once` store open unchanged | none |
| N-11 SIEM drain no flush | ACCEPTED | `siem_integration.go:~222` `drain()` unchanged; audit log is the record of truth, drops are counted (`SIEMEventsDropped`). Add one line to the SIEM docs | `TestSIEMFullQueueDoesNotBlock` |
| N-12 `extractSourceIP` returns `host:port` | OPEN | `audit_events.go:~138` still `return r.RemoteAddr`; only reached when `ClientIP` is empty | none |
| N-13 `include_chain` silent leaf | OPEN | `certificate_ca_provider.go:869-882` logs and returns the bare leaf with 200; comment documents it | `TestCACertificateProviderDownloadIncludeChain` (success only) |

Summary: the 2 partials and N-01..N-04 are all FIXED or ACCEPTED (FB-02 fixed, FB-04 accepted, N-01 to N-04 fixed). Of the LOWs N-05..N-13:
N-07 fixed, N-11 accepted, 7 open (N-05, N-06, N-08, N-09, N-10, N-12, N-13; N-09 slightly worse). All open LOWs are carry-over, not regressions.

## 2. Delta review by dimension

**Complexity.** Changed-file scan: no function crossed into the 40+ cyclomatic range. Worth noting:
`runScan` is unchanged at cognitive 59 (RC1 recommended extracting the per-candidate auto-renew `switch`; not done) and
cyclomatic 25 to 27 (two new `case` arms for tenant and stamp). The registration closures grew mostly from pasted 413 blocks and the
egress gate: `registerCertificateHandlers` 351 to 371 cognitive, `registerTemplateHandlers` 204 to 220, `registerKeyHandlers` 144 to 160,
`registerTargetHandlers` 125 to 144 (cyclo 49 to 56). New over-threshold functions: `scanAuditFile` (cognitive 26, streaming loop, justified),
`filterFileCertificates` (31, extracted from `fileCertificateProvider.ListCertificates` 36, a net improvement), `resolveRSAPublicKeyByKID` 22,
`registerCodeSigningHandler` 21, `parseTemplatePatchRequest` 21. Improvements: `caCertificateProvider.ListCertificates` (36) and
`applyManagedTargetUpdate` (cognitive 25) dropped under threshold via `mergeManagedTargetUpdate` and the index; `computeCryptoPostureReport` 28 to 24;
`NamePolicy.Check` 31 to 25.

**Duplication.**
- 413 handling (RC2-M1): `rejectOversizeBody` (`request_body.go:84`) has 10 callers (templates x4, certificates x5, credentials x1), while 11 other sites inline the same
  `if isBodyTooLarge(err) { writeErrorEnvelope(w, 413, "payload_too_large", "request body too large"); return }` (keys x4, byok, templates x3, delivery plugins, estate,
  codesign, scep challenges, certificates:823), plus `decodeJSONBodyOrReject` and a third wording at `handlers_pending_actions.go:75`. Two branches landed the same fix two ways.
  Consolidate onto `rejectOversizeBody` (one `sed`-able pattern, about 11 sites), delete the inline copies; note `isBodyTooLarge` then needs no other caller outside `request_body.go`/`scim.go`.
- Env-bool: `envBool`, `envBoolDefault`, `envTrue` (cmd), plus 9 inline comparisons (N-08).
- Identity kind: `egressStamp` (kind from `AuthType`, reference from Kid/ID) and `canonicalHuman` (human from `AuthType`/Kid/CreatedBy) are two parallel `AuthType` switches that
  must stay consistent (a stamped `key:<kid>` is re-verified by key record, a grant by canonical human). They are not duplicate logic, but they share one unowned vocabulary (RC2-M2).
- Expiry bucketing is implemented three times: `computeCryptoPostureReport`, `computeExpiryTimeline`, and `tallyExpiry` (compliance); this delta made all three agree on "unknown", but they
  should share one classifier (RC2-L9).
- `algorithmOfPublicKey` (`keystore/software.go`) re-implements the RSA/EC/Ed25519 ladder that `ca.PublicKeyBits` (`ca/key_strength.go`) already has (RC2-L10).
- Test infrastructure: `handlers_oversize_body_test.go` (`writeGateHarness`) and `oversize_413_test.go` (inline mux) cover disjoint route sets with different harnesses (RC2-L12).

**Error handling.** No new swallowed errors of consequence in non-test added code (`_ =` hits are `Close()` in cleanup paths and one `json.Marshal` of a `map[string]string`).
Fail-open points introduced, all documented in code and none exploitable on its own:
`principalIDReserved` returns false on a user-store error (`principal_reserved.go`, "not a reason to block key minting": an API key can then carry a human's id while the store is down; LOW, RC2-L5);
`validateTargetReferences` maps any credential/plugin store `Get` error to "does not name a credential" (outage looks like a typo; LOW, RC2-L6);
`verifyEgressStamp` accepts `token:` (jwt/oidc) and `bootstrap` stamps without re-check (documented); rate limiter drops an arbitrary live key at the 100k cap (`ratelimit.go` `makeRoomLocked`; bounded memory over exact counts, documented; LOW, RC2-L11).
Fail-closed work is good: audit store startup, user-store outage in `currentUserRole` (push skipped), unreadable audit history, `RejectPlaceholderSecret`, grant binding "belongs to a different principal" (generic on purpose).

**Type safety.** `reissue_required` is **not** a typed enum: the vocabulary is one switch (`validRenewalStatus`, `certificate_provider.go:213`, comment ties it to migration 000073 and openapi),
but the error text at `certificate_ca_provider.go:1062` re-lists the five values by hand, `key_lifecycle.go:370` and `certificate_index.go:88` use bare `"reissue_required"`/`"active"` literals,
`inventory_source.go:294` bare `"revoked"`, and the UI mirrors it in `Certificates.tsx` (`<option>`, `=== "reissue_required"`). `renewal_status` is `string` end to end; the generated API type does carry the enum on the UI side (RC2-L3).
The auth-kind case is the sharper one (RC2-M2).

**Pattern consistency.** New handlers follow the surrounding style (`authorizeTargetEgress` returns four values, `fields, stamp, allowed, need`; a small struct would match
`decodeJSONBody`-style helpers better; LOW, RC2-L8). `registerTargetHandlers` gained a `targetEgressDeps` parameter and the exported wrapper `RegisterTargetHandlers` gained two parameters
(`credentials`, `plugins`), which is a public signature change inside the module only. UI delta is one 15-line change in `Certificates.tsx`: `formatStatus` is local, null-safe, and consistent with `Badge` tone logic. No `any`, no assertions.

**Comment accuracy.** Stale or misleading:
- `siem_integration.go:12-13` package header still lists "cert.issued, cert.revoked, cert.expiry_warning, ca.created, ca.suspended, auth.login_failed, auth.login_success" as the supported types
  (RC2-L1); the body now says every action is forwarded. `cefEventNames` comment ("historically emitted") is correct.
- `handlers_reports.go:167` "Fetch up to 10,000 certificates for aggregation" while the ceiling is `reportCertificateCeiling = 1_000_000` (RC2-L2).
- `agentinstall/verify.go:27-34`: two doc comments run together; the one above `DefaultVerifier` ("the TLS-dial verifier the built-in installers use ... for delivery plugins") describes `defaultVerifier`, and
  `DefaultVerifier` itself is now unreachable (see Dead code) (RC2-L4).
- `managed_target_store.go` `applyManagedTargetUpdate` doc still reads "INSERT-or-nothing... actually via a plain UPDATE" (pre-existing rambling, moved in this diff).
- `renewal_scheduler.go:~761`/N-02 uses `time.Now()` where `runScan` already carries `now` (L7). `ratelimit.go` field comment "Changing the env var therefore needs a restart" is correct for the limiter but contradicts nothing in `clientip` (which now follows env changes).

**Dead code introduced.** `agentinstall.DefaultVerifier` (exported wrapper) lost its last production caller when plugins moved to `HubVerifier` (`renewal_plugin.go:176`); `deadcode -test` now lists it (RC2-L4).
`autoRenewOutcome.attempted` (N-05) persists. `WithConnectorRegistry` (N-10) persists. `certificateIterator` fallback `pageEachCertificate` is live (test doubles) and covered by `inventory_iteration_test.go`.

**Test quality on new security paths.** Strong. Every RC1-A/B/C security fix has a named test: `egress_stamp` and `handlers_targets_egress_test.go` (206 lines), `separation_of_duties_entrypoints_test.go` (172, entry-point matrix),
`key_dual_control_test.go` and `key_egress_dual_control_test.go` (grant bound to credential), `name_policy_test.go`, `handlers_renewal_profile_test.go` (78), `renewal_threshold_bounds_test.go`, `audit_file_provider_test.go` (410, migration, torn tail, fail-closed open),
`inventory_iteration_test.go` (409), migration up/down tests including live Postgres (`migrate_renewal_status_postgres_test.go`). Gaps: no test for the `MkdirAll` fatal (needs an `os` seam; LOW);
`N-13` has no failure-path test; no test asserts that a new `AuthType` value cannot get a `token:` stamp by default (RC2-M2).

## 3. New findings

### MEDIUM
**RC2-M1 Oversize-body 413 handling is half-consolidated** (conf 95). See Duplication. 11 inline copies beside 10 helper callers; this is where most of the closure-size growth in section 2 comes from.
Fix: replace every inline block with `if rejectOversizeBody(w, err) { return }` (mechanical, one script), fold `handlers_pending_actions.go:75` onto the standard text, delete the extra `isBodyTooLarge` imports of intent. Effort S.

**RC2-M2 Egress stamp defaults any unknown `AuthType` to an unverifiable `token:` stamp** (conf 80). `egress_stamp.go:30-38`: `bootstrap`, `api-key`, `local`, and `default -> token:`; `verifyEgressStamp` accepts `token:` with no re-check.
Today the only other values are `jwt` and `oidc` (verified by grep), so this is correct now. A new auth type (for example SAML sessions, whose guard file exists) would silently become a never-revoked egress authority, where the sibling code
(`auth.go` fail-closed for `local`) is explicit. This is the concrete cost of N-09. Fix: `type AuthType string` with consts in one place; make `egressStamp` an exhaustive switch whose default returns "" (refuse to arm) and add a test that iterates every AuthType const. Effort S-M.

**RC2-M3 `runScan` still the heaviest non-registration function and still untested as a unit** (conf 85). Cognitive 59 (baseline 34), cyclomatic 27, now with five `case` arms
(tenant, stamp, serr, successor, attempt) and per-candidate logging. RC1 recommended extracting the auto-renew `switch`; the delta added arms instead. Extract `s.autoRenewCandidate(ctx, cert, target, st, serr, now) autoRenewOutcome`. Effort M. Carried from RC1 (accepted for rc.1/rc.2, should not be accepted again).

### LOW
- RC2-L1 SIEM package header lists 7 event types (`siem_integration.go:12-13`); update to "every audit action; seven keep legacy names", point at `KRYPTKEEPER_SIEM_ACTIONS`.
- RC2-L2 `handlers_reports.go:167` stale "10,000" comment. Also: `reportCertificateCeiling` of 1,000,000 lets one report hold the full inventory in memory (`listAllCertificates` builds a slice); acceptable at the stated 50k scale, flag for `/perf`.
- RC2-L3 `renewal_status` is a bare string with literals in 7 places and a hand-copied error message; add `type RenewalStatus string` consts and derive the message from them.
- RC2-L4 `agentinstall.DefaultVerifier` is dead and its doc comment is merged with `defaultVerifier`'s; delete the wrapper or fix the comment.
- RC2-L5 `principalIDReserved` is fail-open on user-store error and does a full `ListUsers` scan per key mint.
- RC2-L6 `validateTargetReferences` returns "unknown credential/plugin" for store outages; return `errTargetStoreUnavailable` (503) when the error is not not-found.
- RC2-L7 `installState` timestamp fallback uses `time.Now()` instead of the scan's `now`; harder to test deterministically.
- RC2-L8 `authorizeTargetEgress` four-value return (`fields, stamp, allowed, need`); use a small result struct. Also `gate()` builds JSON with `fmt.Sprintf("%q")` (`key_dual_control.go`), which is Go quoting, not JSON, for non-ASCII; use `json.Marshal`.
- RC2-L9 Three independent expiry bucketers (posture, timeline, compliance `tallyExpiry`).
- RC2-L10 `algorithmOfPublicKey` duplicates `ca.PublicKeyBits` ladder.
- RC2-L11 Rate-limit cap eviction drops an arbitrary live key (documented trade-off); consider evicting the oldest-seen instead, so an attacker minting keys cannot target eviction of a specific victim's counter by luck.
- RC2-L12 Two oversize-body test files with two harnesses; merge into one table after RC2-M1.
Open RC1 LOWs (N-05, N-06, N-08, N-10, N-12, N-13) are listed in section 1 and not repeated here.

## 4. Tool delta (whole tree, RC1 baseline `scratchpad/rc1/health/` vs RC2 6200a0d)

| Tool | RC1 | RC2 | Delta |
|---|---|---|---|
| gocyclo >15 | 129 | 129 (131 raw; 2 are in `sdk/delivery-go/abi`, a separate module not scanned in RC1, unchanged by this diff) | net 0: left the list `caCertificateProvider.ListCertificates` 23, `fileCertificateProvider.ListCertificates` 26, `applyManagedTargetUpdate` 27, `LoginContext` (new 16, extra arm); entered `filterFileCertificates` 21, `mergeManagedTargetUpdate` 18; `runScan` 25 to 27; `registerTargetHandlers` 49 to 56; `registerKeyHandlers` 53 to 57 |
| gocognit >20 | 120 | 121 (123 raw, 2 in `sdk/` and `tests/plugins`) | `scanAuditFile` 26, `resolveRSAPublicKeyByKID` 22, `registerCodeSigningHandler` 21, `parseTemplatePatchRequest` 21, `filterFileCertificates` 31 enter; `caCertificateProvider.ListCertificates` 36, `scanKeyReuse` 22, `applyManagedTargetUpdate` 25 leave; `main` 288 to 282; registration closures +16 to +20 each |
| staticcheck | 75 | 75 | identical diagnostic set |
| deadcode -test | 39 | 40 | +`agentinstall.DefaultVerifier` (RC2-L4); no other change |
| gofmt -l | 4 files | 0 files | fixed (`8e549ec6 style: gofmt remaining files`) |
| jscpd Go (min-tokens 100) | 19 clones, 383 dup lines, 0.50% (76,704 lines) | 18 clones, 369 dup lines, 0.46% (80,919 lines) | -1 clone; the token-level metric does not see the 413 blocks (below 100 tokens each), which is why RC2-M1 comes from reading, not from jscpd |

Method: `gocyclo -over 15 .`, `gocognit -over 20 .` over the whole module excluding `_test.go` for the comparison (the raw runs include test files and `sdk/`, 184/161 lines;
RC1 excluded them), `staticcheck ./...`, `deadcode -test ./...`, `gofmt -l .`, `jscpd@4.0.5 --min-tokens 100 --format go --ignore "**/*_test.go,**/generated/**"`. Raw outputs in the session scratchpad `rc2/`.
The UI delta is `Certificates.tsx` only (plus generated `api-types.ts`, excluded); not separately linted here.

## 5. Recommended before 1.0 (none gate rc.2)
1. RC2-M1: one-script consolidation of the 413 blocks onto `rejectOversizeBody`.
2. RC2-M2 with N-09: `AuthType` and `RenewalStatus` typed consts; exhaustive stamp switch.
3. RC2-M3: extract the auto-renew arm from `runScan`.
4. Comment fixes RC2-L1, L2, L4 (five minutes) and delete `DefaultVerifier`, `autoRenewOutcome.attempted`, and the no-op `if` in `emitAuditEventDetail`.
