# Challenge Report: Code Health Review, 2026-10-09 (main 6062c62)

Scope: every HIGH/CRITICAL item in `CODE_REVIEW_2026-10-09.md` that the coordinator had not already verified. Each cited file:line was opened in the worktree. Coordinator-verified (not re-challenged): CX-001, DUP-001, DEAD-001, DEAD-002, SA4010/DEAD-010, SA4023.

| Finding | Verdict | Evidence (quote from code) |
|---|---|---|
| CX-002 compliance evidence ignores empty/unparseable expiry | CONFIRMED | handlers_reports.go:1149-1153 `if c.ValidUntil == "" { return false }` ... `return err == nil && t.Before(now.Add(30*24*time.Hour)) && t.After(now)`; the `expired` closure at :1156-1160 has the same shape, so unknown expiry is in neither bucket. Not verified: the claim that the resulting control status is `pass` (status logic after :1163 not read) and that `warn` is unreachable below 10 certs. |
| EH-001 audit append failure log-only, cancellable ctx | CONFIRMED | audit_events.go:48-49 `if err := auditProvider.AppendEntry(r.Context(), entry); err != nil { log.Printf("audit append failed action=%s: %v", action, err) }`; function returns nothing. Not verified: the "831 call sites" figure and whether providers honour ctx cancellation. |
| EH-002 deprovisioned check fails open (2 sites + refresh) | CONFIRMED | auth.go:239 `derr == nil && deprovisioned`, rationale at :233-238 "derr != nil ... is deliberately treated as 'not deprovisioned'"; handlers_auth.go:236 `err == nil && deprovisioned`; auth_identity.go:162-163 "A user-store *error* fails open ... (see Refresh)". |
| EH-003 executed action, Decide failure returns 409 with no audit row | CONFIRMED | handlers_pending_actions.go:214-217 `if err := store.Decide(r.Context(), id, "approved", pd.ID, result); err != nil { writeConflict(w, err.Error()); return }` precedes `emitAuditEvent(... "action.approve" ... "success")` at :217-218. The execute call is above at :196-198. |
| TS-001 roles are untyped literals | CONFIRMED | `grep '"pki-admin"'` over non-test Go in internal/ = 14 lines (matches the finding); handlers_pending_actions.go:30-31 `switch role { case "pki-admin", "pki-operator": return true`; the only role const is `RoleMCPAgent` (mcp_role.go:7). |
| DUP-002 http-01 deny-list weaker than egress | CONFIRMED | http01.go:34-35 `ip.IsLoopback() \|\| ip.IsLinkLocalUnicast() \|\| ... IsMulticast() \|\| ip.IsUnspecified()` with only `Unmap()`; egress.go:71-77 unwraps `nat64Pfx` and egress.go:81 blocks `thisNet`. http-01 has neither (0.1.2.3 and `64:ff9b::a9fe:a9fe` pass). |
| DEAD-003 exceptions can never be created | CONFIRMED | `grep FindingException` outside tests and outside finding_exception_store.go shows only readers (`activeFindingExceptions`, funnel computation); `Create` is defined at finding_exception_store.go:148,203 and has no non-test caller; no route registers an exceptions handler. docs/openapi.yaml:581-606 describes exception-aware reports. |
| DEAD-004 non-ACME issuer connectors inert | CONFIRMED (severity adjusted) | handlers_connectors.go:27-38 switch has only `internal` and `acme`, `default: return nil`; `NewDigiCertConnector/NewESTClient/NewSCEPClient/NewWSTEPClient` have no caller outside internal/connectors and tests. Adjustment: handlers_connectors.go:96 already reports health "unknown ... no runtime implementation", so the listing is honest; downgraded from release-blocking to Wave B (HB-09). DigiCert INVENTORY sources (inventory_source.go) are a separate, working path. |

## Adjusted but not contradicted

| Item | Adjustment | Evidence |
|---|---|---|
| DUP-003 CMP replay cache evict-oldest | Severity lowered MEDIUM to effectively LOW | cmp/server.go:134 comment "Only authenticated messages are recorded, so unauthenticated junk" cannot flush the cache; flushing needs valid credentials. replay.go:56-65 does evict live entries when `len(order) >= max` as claimed. |
| FB-08 as release-blocking | Dropped (see DEAD-004 above) | handlers_connectors.go:96 |

## Result

8 challenged, 8 CONFIRMED, 0 CONTRADICTED, 0 UNVERIFIABLE. Two sub-claims inside findings were not verified (CX-002 control status, EH-001 call-site count); both are labelled in the table and neither changes the item's disposition. No findings dropped.

Residual note for the release owner: FB-13 (`publicKeyBits`) and FB-14 (pre-auth body limits) are marked release-blocking on judgment, not on a challenger-verified exploit. They come from the Anti-Slop and Pattern specialists at MEDIUM and were not independently re-challenged here.
