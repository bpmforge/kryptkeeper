# Code Health Review: Kryptkeeper (main 6062c62), 2026-10-09

Synthesizer over seven specialist reports (`*_FINDINGS_2026-10-09.md`) plus coordinator-verified items.
Companions: `FIX_BACKLOG_code-health_2026-10-09.md` (prioritized, wave-planned), `CHALLENGE_REPORT_code_2026-10-09.md`.
Security-routed items do not re-file anything fixed by FG-1..FG-14 (`docs/security/final-report.md` section 5). FG-6a/6b (tenant isolation) is deferred to v0.10 under the owner decision in section 6; nothing here re-files it.

## Verdict for the public-release gate

**NOT READY for public v0.9.0 as-is. Conditional GO after Wave A (13 release-blocking items).**

No finding is a remote-unauthenticated compromise (the specialists found no CRITICAL individually). The blockers share one shape: the code looks finished and is tested, but a safety or durability behavior is silently absent in production. Three are disconnected features that report "configured" or "works" (SIEM, upstream renewal, finding exceptions). Three are fail-open or silently-degraded security paths (policy gate, deprovisioned-user check, second-root mint). Two are audit-loss paths. Three are weak or wrong security data (XFF rate-limit bypass, http-01 NAT64 gap, compliance evidence and key-size gaps). One is a pre-auth unbounded body. All Wave A fixes are small or medium, and they partition into 6 non-colliding agents (section "Waves" in the backlog).

After Wave A the remaining items are hygiene and refactors with no known silent-failure behavior. Wave B should land before public release if time allows; it does not gate it.

## Health Dashboard

| # | Dimension | Score /10 | Specialist | Headline |
|---|---|---|---|---|
| 1 | Complexity | 6 | Complexity | `main()` cyclo 133 / cog 304 hides two fail-open branches; ~45% of tool hits are benign route tables |
| 2 | Duplication | 6 | Duplication | Low clone rate (0.54% Go) but two security checks diverged (client IP, dial deny-list) |
| 3 | Error Handling | 6 | Error Handling | Disciplined style; audit loss, one fail-open (A2A7-009), approval bookkeeping gap unremediated |
| 4 | Type Safety | 7 | Type Safety | UI very clean; Go roles/permissions/statuses are bare strings on the authz path |
| 5 | Pattern Consistency | 6 | Pattern | Strong auth/error/audit idioms; body limits, env parsing, JSON writers drifted |
| 6 | Naming | 8 | Pattern | One misnomer (`checkSAMLResponseFreshness` mutates) |
| 7 | Comment Accuracy | 7 | Pattern + Anti-Slop | One stale security comment, a stub papered over by comment, narration blocks |
| 8 | Dead Code | 5 | Dead Code | 4 HIGH disconnected pipelines with green tests; 155 unreachable (43 with tests) |
| 9 | Tech-Stack Compliance | 4 | Pattern | 12 Go and 11 UI direct deps absent from TECH_STACK.md; validator passes vacuously |

Unweighted mean 6.1/10. Anti-Slop (not a scored dimension): overall level LOW, 0 TODO/FIXME, 1 real stub (`publicKeyBits`), 1 import-suppression hack.

Finding counts after dedup (see backlog): 0 CRITICAL individual and 12 HIGH after merging (listed below); MEDIUM and LOW are itemised in the backlog. 5 compound-risk modules (section below) are escalated one level.

## Compound-Risk Modules (highest priority)

Rule applied: 3+ specialist dimensions on one module escalates to max(severity)+1. Co-hit counts are distinct specialists.

### CR-1 internal/bootstrap auth/authz: CRITICAL compound (6 specialists)
Findings: EH-002 (fail-open deprovision check, 2 sites + Refresh), EH-007 (role-map validation passes on store error), EH-008 (missing tenant claim becomes default tenant), TS-001/002 (14 production `"pki-admin"` literals, 4 parallel role allowlists, untyped permission strings), DUP-004 (role store built 2-3 times), DUP-007 (JWT claim validation cloned between HS256 and JWKS), CX-003 (`NewAuthenticatorFromEnv` cyclo 74, env flag idiom hand-rolled 6 times), P-05 (5 bool-env idioms).

Why it multiplies. The decision that matters is "may this principal act?" and it is made in several places that must agree. (1) The deprovision check fails open, and the same expression is copied in `auth.go:239`, `handlers_auth.go:236` and the refresh path, so a fix must hit three sites. (2) The role that check feeds is compared as a bare string against at least four allowlists (`canApproveActions`, `authz_ops.go`, `authz_write_gate.go`, `authz_custom_roles.go`), so a missed site compiles and silently turns a grant into a deny or a deny-list into a never-match. (3) The token claims feeding it are validated by two cloned verifiers that can drift. (4) The configuration that picks the mode is a 200-line env parser that cannot be unit tested without about 40 `t.Setenv` calls. Any one of these is MEDIUM. Together a single missed site is invisible to the compiler, the tests and the reviewer. Fix order: type the roles first (cheap, mechanical, compiler-checked), then change the fail-open behavior with a regression test, then dedupe claims.

### CR-2 cmd/kryptkeeper main.go startup: CRITICAL compound (4 specialists)
Findings: CX-001 (cyclo 133, policy-engine error dropped, `ListCAs` error read as "no CAs"), DEAD-002 (renewal connector registry never wired at main.go:324), DEAD-005 (CT monitor store built but unreachable from API), TS-006 (typed-nil `*VaultStore` into `Store`), P-05 (`BOOTSTRAP_CREATE_ROOT` compared case-sensitively), EH (unchecked `MkdirAll`).

Why it multiplies. The composition root is the one place where "is this feature actually connected?" is decided, and it is a 1,200-line function with `log.Fatal` inside, so it has no tests. The complexity is what makes the swallowed errors invisible; the swallowed errors are what make the disconnected wiring invisible (nothing logs that the policy gate or connector registry is absent). Three of the five defects here are silent by construction. Splitting `main()` into `buildKeystore / buildCAEngine / resolveDefaultCA / startSchedulers` that return errors is the structural fix and turns each wiring decision into a testable function.

### CR-3 audit path (audit_events.go, handlers_pending_actions.go, siem_integration.go): HIGH compound (4 specialists)
Findings: EH-001 (append failure is log-only, uses the cancellable request ctx), EH-003 (approved action executes, bookkeeping failure returns 409 with no audit row), DEAD-001 (SIEM forwarding has no caller), EH-004 (raw errors echoed), DUP-003-style bounded-cache copies elsewhere.

Why it multiplies. There is one audit sink for 831 call sites, so a single defect has fleet-wide reach. Today a failed append drops the row and a hung-up client cancels the ctx so the row is dropped even when the DB is healthy. Even where the row is written, nothing is forwarded to the SIEM the operator configured. The two protections are layered (local trail, then external copy) and both are absent, so a destructive action can complete with no durable record anywhere. The fix is also single-point: one change in the sink protects all callers, and the SIEM hook belongs in the same function.

### CR-4 trust-boundary helpers (ratelimit, bootstrap/auth_rate_limit, acme/http01, egress): HIGH compound (4 specialists)
Findings: DUP-001 / P-08 / P-01 (two `clientIP` implementations trusting different headers, one stale comment), DUP-002 (http-01 deny-list weaker than `internal/egress`), P-06 (`APP_TRUSTED_PROXY_CIDRS` undocumented in env.example), DUP-005 (EST vs CMP suffix matchers diverged).

Why it multiplies. Copy-paste of a security check, justified in comments by "ticket write-scope", produced divergence in the weaker direction twice. The stale comment tells a reader the bypass was fixed when it was not, and the missing env documentation means operators behind a proxy will not set the variable that makes the limiter correct. Single shared implementations (`ratelimit.ClientIP`, `egress.Policy.DialControl()`) close the whole class.

### CR-5 compliance and inventory data (handlers_reports.go, handlers_evidence.go, certificate_ca_provider.go): HIGH compound (4 specialists)
Findings: CX-002 (unparseable or empty `ValidUntil` counts as neither expired nor expiring), EH-005 (CA list error ignored in the evidence pack), S-01 (`publicKeyBits` returns 0 for every cert), CX-005 (risk score and risk flags duplicate the same ladder), EH-006 (PQC countdown empty on store error).

Why it multiplies. These feed documents operators hand to auditors. Each defect fails toward "looks fine": unknown expiry passes, missing CA data passes, key size 0 defeats weak-key flags. Overlapping a duplicated rule ladder (score vs flags can disagree) means the report can be internally inconsistent without any single bug being visible. Evidence artifacts must stamp or fail on missing data.

## Merged findings (deduplicated)

| Merged id | Absorbs | Sev | Module |
|---|---|---|---|
| CX-001 | TS-006, P-05(main.go:213) | HIGH (VERIFIED) | cmd/kryptkeeper |
| EH-001 | | HIGH | bootstrap/audit |
| EH-002 | A2A7-009 (known) | HIGH | bootstrap/auth |
| EH-003 | EH-004 (pending-actions part) | HIGH | bootstrap/approvals |
| DUP-001 | P-01, P-08, P-06(proxy var) | HIGH (VERIFIED) | ratelimit, bootstrap |
| DUP-002 | | HIGH | acme, egress |
| DEAD-001 | | HIGH (VERIFIED) | bootstrap/siem |
| DEAD-002 | DEAD-004 (SCEP renewal branch) | HIGH (VERIFIED) | bootstrap/renewal |
| DEAD-003 | | HIGH | bootstrap/exceptions |
| DEAD-004 | | HIGH | connectors |
| TS-001 | TS-002, TS-003 | HIGH | bootstrap/authz |
| CX-002 | EH-005, CX-005 | HIGH | bootstrap/reports |
| EH-009 | DEAD-010, SA4010 | LOW (VERIFIED) | crl |
| EH-004 | P-03, P-04 | MEDIUM | bootstrap, est, cmp |
| S-01 | S-05 (comment), P-10 (acme comment) | MEDIUM | bootstrap/cert provider |
| P-02 | | MEDIUM | bootstrap (25 sites) |
| DUP-003 | | MEDIUM, downgraded: CMP cache records only authenticated messages (cmp/server.go:134) | cmp, acme, bootstrap |
| DUP-004, DUP-005, DUP-006, DUP-007 | | MEDIUM/LOW | various |
| CX-003..CX-010 | | MEDIUM/LOW | various |
| P-05, P-06, P-07, P-09, P-10, P-11 | | MEDIUM/LOW | various |
| DEAD-005..009, DEAD-011..015 | | MEDIUM/LOW | various |
| SA1019 (acme jws.go:214, store_sqlite.go:242) | | MEDIUM if on-curve check dropped | acme |
| SA4023 main.go:134 | | INFO, build-tag false positive | cmd |

## Disconnected-feature guidance (wire vs remove)

| Item | Recommendation | Reason |
|---|---|---|
| DEAD-001 SIEM | Wire | One async call in the audit sink, same file as EH-001; operators already configure it |
| DEAD-002 upstream renewal | Wire, and fail closed meanwhile | Registry build is a one-liner at main.go:324; until wired, refuse (not silently hub-renew) a cert pinned to a connector |
| DEAD-004 digicert/est/scep/wstep | Not a blocker: connector listing already reports health "unknown, no runtime implementation" (handlers_connectors.go:96). Reject unsupported types at create and label roadmap (Wave B HB-09) | Four clients with no config decode or credential handling; wiring is L feature work. (DigiCert INVENTORY sources are separate and do work.) |
| DEAD-003 exceptions | Hide claims for v0.9; wire in v0.10 | Create flow needs handler, proposer != approver, audit, UI (L); today "suppressed" is always 0 |
| DEAD-005..009 | Owner decision per feature, Wave C | None silently harms a security property |

## Positive observations

Auth and audit idioms are very consistent (110 `AuthenticatePrincipalDetails` sites, 774 `emitAuditEvent`, single error-envelope helper). Crypto and protocol packages (`ca`, `acme`, `keystore`) have moderate, commented ladders with explicit check ordering. UI has 0 `as any`, 0 `@ts-ignore`, 0 non-null `!` in production. Security tests assert denied paths, not just `err == nil`. No `panic` on request paths. Revocation emits failure and success audit on every branch.

## Limits

`tsc` and knip could not run (no `node_modules` in the worktree); no UI error counts claimed. Duplication findings DUP-006..009 rely on jscpd locations and were not read line by line. The compound-risk escalation uses specialist severities, not re-scored ones. Challenger results: see `CHALLENGE_REPORT_code_2026-10-09.md` (0 contradicted).
