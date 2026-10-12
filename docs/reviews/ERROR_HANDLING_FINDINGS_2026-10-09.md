# Error Handling Findings — Kryptkeeper @ 6062c62 — 2026-10-09

Scope: Go (primary), UI (secondary). Read-only review. Module key = package dir.
Score (Error Handling dimension): **6 / 10**. Disciplined style (blocked-by-comment `_ =` sites, logged audit failures, typed sentinels, no empty catches in UI) but audit loss and one fail-open path are by-design and unremediated.

Counts: HIGH 3 | MEDIUM 4 | LOW 3  (10 findings; all confidence >= 75)

## Scan results
- Empty `catch {}` / `.catch(() => {})` in UI: 7 `.catch(() => {})` on `mutateAsync` (App.tsx:157, Alerts.tsx:399/505/837/925, CAs.tsx:803/842/866). All sit on mutations whose `onError` toasts (e.g. Alerts.tsx:116) -> not swallowed. App.tsx:157 logout is intentional.
- Go `_ =` on error-returning calls: ~55 in internal/bootstrap; nearly all carry a justification comment (Close, Unmarshal-then-validate, dbProviderUnavailable logs itself). Only EH-005/006 below are real.
- Audit-emit callers: 831 call sites of `emitAudit*` across bootstrap; one sink (audit_events.go) -> findings are systemic, fixed in one place.
- Raw `err.Error()` to HTTP clients: bootstrap/handlers_discovery.go 3, est/server.go 3, cmp/server.go 2, bootstrap/handlers_cas.go 1, handlers_agents.go 1, handlers_pending_actions.go 4, est/auth.go 1, wstep/server.go 1.
- `panic(` on request paths: none. Panics are constructor nil-guards (handlers.go:63-90) and ca/engine.go:891 (crypto/rand dead = correct). Request-data type assertions all use the `, _ :=` two-value form (auth_jwks.go:38,43,109; auth_hs256.go:35,98; auth_identity.go:280) -> fail to zero value, not panic.
- staticcheck triage (non-deprecation): SA4023 main.go:134 = FALSE POSITIVE (pkcs11_stub.go, `!pkcs11` build tag, always returns error; real build can return nil err). No action; consider `//lint:ignore`. SA4010 crl/generator.go:81 `append` result unused — see EH-009. SA4006 scanner.go:395 / handlers_reports_test.go:874 — dead assignments, not error-related. U1000 items are dead-code (other reviewer).

---

## HIGH

### EH-001 [HIGH] [module: internal/bootstrap] [→ security-auditor] Audit-append failure is log-only; the action has already committed (silent audit loss)
- internal/bootstrap/audit_events.go:48
  `if err := auditProvider.AppendEntry(r.Context(), entry); err != nil { log.Printf("audit append failed action=%s: %v", action, err) }`
- Fails: audit DB down/locked/disk full, or `r.Context()` already cancelled (client disconnect/timeout after the action ran — the audit write uses the request ctx, so a hung-up client silently drops the row). `emitAuditEventDetail` returns nothing, so none of the 831 call sites (issuance, revoke handlers_certificates.go:~520, key ops, approvals) can react.
- Now: cert issued / revoked / key destroyed, HTTP 200, no audit row, only a stderr line. Violates "anything you cannot reconstruct from the audit log is a bug".
- Fix: (1) append with `context.WithoutCancel(r.Context())` + short timeout; (2) make emit return error and have security-critical sites (issue, revoke, key ops, approve) either append a pre-action "intent" row before acting (fail closed) or surface 5xx/`audit_degraded` header + metric; (3) add a durable local fallback (spool file / WAL) and counter `audit_append_failures_total` for alerting.
- Confidence: 95

### EH-002 [HIGH] [module: internal/bootstrap] [→ security-auditor] Deprovisioned-user check FAILS OPEN on user-store error (known A2A7-009; two sites)
- internal/bootstrap/auth.go:239
  `if deprovisioned, derr := principalIsDeprovisioned(...); derr == nil && deprovisioned {` (rationale comment at :233-238)
- internal/bootstrap/handlers_auth.go:236 same pattern `err == nil && deprovisioned` in /authz-check.
- Fails: `ListUsers` error (DB outage, timeout). Result: a SCIM-deactivated user with an unexpired JWT is ALLOWED on every authenticated request for the duration of the outage (and an attacker able to induce user-store errors — pool exhaustion — can resurrect a revoked identity). No log, no audit row on the error branch.
- Also: `Refresh` (auth_identity.go:162 ref.) is documented to share this check — same fail-open for refresh-token minting.
- Fix: distinguish principal class: only exempt `AuthType` bootstrap/API-key (not UserProvider-managed) from the check; for user-session JWT principals fail CLOSED on `derr != nil` (503/401) and log + audit `authz.userstore_error`. This preserves the bootstrap-token recovery path the comment protects.
- Confidence: 92

### EH-003 [HIGH] [module: internal/bootstrap] [→ security-auditor] Approved action executes, then bookkeeping failure returns 409 with NO success/failure audit row
- internal/bootstrap/handlers_pending_actions.go:214-216
  `if err := store.Decide(r.Context(), id, "approved", pd.ID, result); err != nil { writeConflict(w, err.Error()); return }` (success audit is emitted only at :217-ish, after this return)
- Fails: Decide error after `executeKeyAction`/`executePendingAction` already ran (e.g. DB blip, or ctx cancelled). A destructive key op or issuance has been performed; the handler returns 409 "conflict" with raw DB error text, emits no `action.approve` row, and leaves the row `executing` (the retry is refused by the CAS at :190). Audit trail shows nothing for a completed destructive action.
- Also :161-162 (`reject`) returns `writeConflict(w, err.Error())` leaking store errors.
- Fix: emit `action.approve` outcome=`executed_unrecorded` BEFORE returning; retry Decide with a non-cancellable ctx; return 500/503 with generic text, not 409; log the db error server-side only.
- Confidence: 88

## MEDIUM

### EH-004 [MEDIUM] [module: internal/bootstrap] Internal/engine error text echoed to clients (CA engine, discovery, approvals)
- handlers_cas.go:96 `map[string]string{"error": "unprocessable_entity", "message": err.Error()}` — raw CA-engine/DB error from `CreateCA` (log line above already records it).
- handlers_discovery.go:306,388,467 same pattern. handlers_pending_actions.go:208,211 `"action failed: "+execErr.Error()` — key-action/CA-engine errors (PKCS#11/Vault/KMS endpoint, paths) go to the approver.
- handlers_agents.go:722 `http.Error(w, err.Error(), 403)` from enrollment gate — reveals gate internals to unauthenticated callers.
- est/server.go:141,182,187; est/auth.go:207; wstep/server.go:277; cmp/server.go:161,171 echo parse/policy errors to unauthenticated protocol clients (EST/WSTEP/CMP). Mostly validation text (acceptable, low sensitivity) but CMP :161 forwards arbitrary issuance errors.
- Key-material check: no path found that formats key bytes into an error; keystore errors wrap backend messages only.
- Fix: map to sentinel/typed errors -> stable public messages; keep detail in server log + audit `ChangeSummary` (truncated).
- Confidence: 82

### EH-005 [MEDIUM] [module: internal/bootstrap] Compliance evidence pack silently built without CA data
- handlers_evidence.go:26 `cas, _ = caProvider.ListCAs(ctx, CAListQuery{Limit: 1000})`
- Fails: CA store error. Result: `computeComplianceEvidence(result.Items, cas.Items, ...)` runs with empty CA list; the signed-off compliance PDF (and scheduled emails) may report CA controls as absent/passing with no indication data was missing.
- Fix: return the error (or stamp "CA data unavailable" in the PDF) — evidence artifacts must not be silently partial.
- Confidence: 85

### EH-006 [MEDIUM] [module: internal/bootstrap] PQC countdown renders empty history on store failure
- handlers_pqc_countdown.go:161 `snapshots, _ = snapshotStore.List(r.Context(), since, 365)`
- Fails: snapshot store error -> HTTP 200 with empty trend (looks like "no history", not an outage). Sibling `waveStore.ListWaves` at :166 handles `err == nil` the same lenient way.
- Fix: log + include `degraded:true` in payload, or 503.
- Confidence: 80

### EH-007 [MEDIUM] [module: internal/bootstrap] Custom-role lookup failure treated as "role known"
- auth_role_map.go:164 `if err != nil { report.addWarning(...); return true }`
- Fails: custom-role store error at startup validation -> an APP_AUTH_ROLE_MAP_JSON entry naming a typo'd/nonexistent role passes validation as valid. Runtime effect depends on how an unknown role resolves in authz (not verified here: confirm unknown role => no permissions, not default). Startup-only, hence MEDIUM.
- Fix: error (fail startup) unless explicit `ALLOW_UNVERIFIED_ROLES`; or re-validate lazily at first use.
- Confidence: 75

## LOW

### EH-008 [LOW] [module: internal/bootstrap] Tenant-claim absent -> DefaultTenant (silent fallback)
- auth_jwks.go:109 / auth_hs256.go:98 `tenant, _ = payload[tenantClaim].(string)`; auth.go resolvePrincipalTenancy `identityTenant = DefaultTenant` when empty.
- When MULTI_TENANCY on, a JWT missing/mistyped tenant claim (non-string) is silently bound to the default tenant rather than rejected. Intentional per W3-01 but a malformed claim should be a 401, not a fallback. Flag for security-auditor if default tenant holds sensitive data.
- Confidence: 78

### EH-009 [LOW] [module: internal/crl] Unused `append` result in CRL generator (staticcheck SA4010)
- internal/crl/generator.go:81 — appended slice never read. If it is meant to carry revoked entries/extensions into the CRL it is a silent omission on a security artifact. Needs a 2-minute read by owner; if dead, delete. Confidence: 75 (impact unverified).

### EH-010 [LOW] [module: ui] Query failure in Certificates detail lookup masquerades as "not found"
- ui/src/pages/Certificates.tsx:628 `} catch { return null; }` inside `certById` queryFn — network/500 errors render as missing cert instead of an error state with retry. Same-file pattern at lib/api.ts:277,310,339,859 (`catch { /* ignore JSON parse */ }`) is fine: falls back to status text.
- Fix: rethrow non-404s so react-query surfaces `error`. Confidence: 80

## Positive observations
- No empty-catch blocks in UI; page-level queries destructure `error` and render error states (verified Agents, Automation, CodeSigning, IssueWizard, Login).
- Revocation (handlers_certificates.go:499-522) emits failure/success audit on every branch and does not echo internal errors (logs, returns "certificate unavailable").
- Approval flow (S-63) already surfaces fail-then-record-fail; CAS before execute prevents double-execution.
- Panics confined to startup guards.

## Prioritised fix order
1. EH-001 (single sink, fixes all 831 sites; ctx.WithoutCancel is a 1-line mitigation).
2. EH-002 (class-based fail-closed).
3. EH-003 (approval executed-but-unrecorded).
4. EH-004/005/006.
