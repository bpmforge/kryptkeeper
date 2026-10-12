# Fix Backlog: Code Health, 2026-10-09 (main 6062c62)

Source: `CODE_REVIEW_2026-10-09.md`. Items are deduplicated; source ids in column 4. Effort S <0.5d, M ~1d, L >1d.
Verified: VERIFIED = coordinator checked code; CONFIRMED = challenger pass (see CHALLENGE_REPORT_code_2026-10-09.md); NO = not re-checked (MEDIUM/LOW).
Route: code = Sonnet worktree agent; security = also needs /security review of the diff; docs = documentation only.
Not re-filed: anything closed by FG-1..FG-14; FG-6a/6b tenant isolation is v0.10 (final-report section 6).

## Release-blocking items (must fix before public v0.9.0): 13

| ID | Title | Sev | Source | Files | Fix | Eff | Verified | Block | Route |
|---|---|---|---|---|---|---|---|---|---|
| FB-01 | Issuance policy gate silently off when policy engine fails to build | HIGH | CX-001 | cmd/kryptkeeper/main.go:186 | Make error fatal, or log WARN "issuance policy gate DISABLED" and refuse issuance unless `KRYPTKEEPER_ALLOW_NO_POLICY=true`. Extract the block into a function returning error | S | VERIFIED | YES | code+security |
| FB-02 | Transient `ListCAs` error plus BOOTSTRAP_CREATE_ROOT mints second root | HIGH | CX-001, P-05 | cmd/kryptkeeper/main.go:211,213 | Check the `ListCAs` error before the empty test (fatal); parse the flag with `envBool` (case-insensitive); check `MkdirAll` error | S | VERIFIED | YES | code+security |
| FB-03 | Deprovisioned-user check fails open on user-store error (A2A7-009) | HIGH | EH-002 | internal/bootstrap/auth.go:239, handlers_auth.go:236, auth_identity.go:162 | Fail CLOSED (503/401, log, audit `authz.userstore_error`) for UserProvider-managed session principals; keep the bootstrap-token and API-key exemption so recovery still works. Regression test with a failing UserProvider | M | CONFIRMED | YES (fail-open authz) | security |
| FB-04 | Audit append failure is log-only and uses the cancellable request ctx | HIGH | EH-001 | internal/bootstrap/audit_events.go:48 | Minimum for v0.9: append with `context.WithoutCancel` plus 5s timeout, add `audit_append_failures_total` metric, return an error from the sink so issue/revoke/key-op/approve sites can return 5xx. Full intent-row/spool design is v0.10 | M | CONFIRMED | YES (audit loss) | code+security |
| FB-05 | Approved action runs, then `Decide` failure returns 409 with no audit row | HIGH | EH-003, EH-004 (pending part) | internal/bootstrap/handlers_pending_actions.go:161,214 | Emit `action.approve` outcome `executed_unrecorded` before returning; retry `Decide` with non-cancellable ctx; return 503 with generic text; log DB error server-side only | S | CONFIRMED | YES (audit loss on destructive op) | code+security |
| FB-06 | SIEM forwarding never receives events (Test button only) | HIGH | DEAD-001 | internal/bootstrap/audit_events.go, siem_integration.go, handlers_integrations.go | WIRE: build one router at startup, call `EmitFromAuditEntry` async and non-blocking from the audit sink (same function as FB-04); failures non-fatal and counted | M | VERIFIED | YES | code |
| FB-07 | Certs pinned to an upstream connector renew from the hub CA | HIGH | DEAD-002 | cmd/kryptkeeper/main.go:324, internal/bootstrap/renewal_executor.go:127,499 | WIRE: `BuildConnectorRegistry` at startup passed to `WithConnectorRegistry`. Also fail closed: when `RenewalConnectorID` is set and registry is nil, return an error, never fall back to hub CA | M | VERIFIED | YES | code |
| FB-09 | Finding exceptions cannot be created; reports always show suppressed=0 | HIGH | DEAD-003 | docs only for v0.9: docs/openapi.yaml, docs/ report text, UI labels mentioning exceptions/suppressed | HIDE for v0.9: drop "suppressed/exception" wording from openapi, docs and UI. Wire (handler, proposer != approver, audit, UI) in v0.10 | S | CONFIRMED | YES | docs |
| FB-10 | Protocol rate limits bypassable via client-controlled leftmost X-Forwarded-For | HIGH | DUP-001, P-01, P-08, P-06 | internal/ratelimit/ratelimit.go:110, internal/bootstrap/auth_rate_limit.go:159-213 (+tests), env.example | One shared `ClientIP` and trusted-CIDR parse (X-Real-IP or rightmost-untrusted XFF); delete duplicate funcs and the stale comment; document `APP_TRUSTED_PROXY_CIDRS` in env.example and the deploy docs | M | VERIFIED | YES | security |
| FB-11 | http-01 dial deny-list weaker than egress (no NAT64, no 0.0.0.0/8) | HIGH | DUP-002 | internal/acme/http01.go:27, internal/egress/egress.go:68 (+tests) | Delete `refuseInternalAddr`; export `egress.Policy.DialControl()` and use `Policy{AllowPrivate:true}`; keep `http01CheckRedirect`. Shared table test incl. `64:ff9b::a9fe:a9fe` | S | CONFIRMED | YES | security |
| FB-12 | Compliance evidence reports false assurance on missing data | HIGH | CX-002, EH-005, CX-005 | internal/bootstrap/handlers_reports.go:1108-1160, handlers_evidence.go:26 (+tests) | Parse `ValidUntil` once; add "unknown expiry" bucket that downgrades control to warn/fail; return error or stamp "CA data unavailable" when `ListCAs` fails; inject `now`; table tests for empty and malformed expiry | M | CONFIRMED | YES | code |
| FB-13 | `publicKeyBits` returns 0 for every cert (weak-key posture defeated) | MED | S-01, S-05 | internal/bootstrap/certificate_ca_provider.go:1093 (+test) | Switch on `cert.PublicKey.(type)` (rsa N.BitLen, ecdsa curve bits, ed25519 256); reuse `ca/key_strength.go`; fix the stale comment at acme/server.go:914 in a follow-up | S | NO (anti-slop read) | YES (judgment: silent wrong security data, trivial fix) | code |
| FB-14 | Pre-auth routes decode bodies with no size limit; agent handlers echo gate errors | MED | P-02 (pre-auth subset), P-03, EH-004 | internal/bootstrap/handlers_auth.go:68,177,354, handlers_agents.go:712-793, scim.go:164,380, new request_body.go (+tests) | New `decodeJSONBody(w,r,max,&v)` (413 vs 400); use on login, refresh, agent register, SCIM; switch agent `http.Error` to envelope helpers with a fixed gate message | M | NO (cited by pattern checker with line refs) | YES (judgment: pre-auth DoS surface; mitigated only by 15s ReadTimeout) | security |

Blocker count: 13 (FB-01..FB-07, FB-09..FB-14; FB-08 was downgraded in the challenger pass, see HB-09). FB-13 and FB-14 are the two judgment calls; if the release owner wants a shorter list, move them to Wave B and record them as accepted risk.

## Fix waves (<=10 files each; agents within a wave do not share files)

### Wave A: release blockers (6 parallel Sonnet worktree agents)

| Agent | Items | Files (non-test) | Total files |
|---|---|---|---|
| A1 startup and renewal wiring | FB-01, FB-02, FB-07 | cmd/kryptkeeper/main.go, internal/bootstrap/renewal_executor.go, handlers_connectors.go (read only for BuildConnectorRegistry) + tests | <=5 |
| A2 auth fail-closed and pre-auth bodies | FB-03, FB-14 | internal/bootstrap/auth.go, auth_identity.go, handlers_auth.go, handlers_agents.go, scim.go, request_body.go (new) + tests | <=9 |
| A3 audit integrity and SIEM | FB-04, FB-05, FB-06 | internal/bootstrap/audit_events.go, handlers_pending_actions.go, siem_integration.go, handlers_integrations.go, metrics wiring + tests | <=8 |
| A4 trust-boundary helpers | FB-10, FB-11 | internal/ratelimit/ratelimit.go, internal/bootstrap/auth_rate_limit.go, internal/acme/http01.go, internal/egress/egress.go, env.example + tests | <=9 |
| A5 report and inventory honesty | FB-12, FB-13 | internal/bootstrap/handlers_reports.go, handlers_evidence.go, certificate_ca_provider.go + tests | <=6 |
| A6 hide exceptions claims | FB-09 | docs/openapi.yaml, docs/*, UI strings (docs and TS text only, no Go) | <=6 |

Collision notes: handlers_auth.go and handlers_agents.go are owned by A2 only (P-02/P-03 pre-auth). main.go is owned by A1 only (FB-07 wiring and FB-01/02 in one agent so the `main()` edit happens once). audit_events.go is owned by A3 only (FB-04 and FB-06 touch the same function). A1 depends on nothing; A3 FB-06 needs main.go to construct the SIEM router: let A3 read the router lazily inside the sink so A1 and A3 stay independent. Merge order: A4, A2, A3, A5, A1, A6 (any order is conflict-free). Security-routed items (FB-01..05, 10, 11, 14) also need a /security look at the diff.

### Wave B: high-value hygiene (after Wave A merges)

| ID | Title | Sev | Source | Files | Fix | Eff | Ver | Route |
|---|---|---|---|---|---|---|---|---|
| HB-01 | Internal errors echoed to clients | MED | EH-004 | handlers_cas.go:96, handlers_discovery.go:306,388,467, est/server.go, est/auth.go:207, cmp/server.go:161,171, wstep/server.go:277 | Map to stable public messages; keep detail in log and audit summary | M | NO | code |
| HB-02 | EST suffix matcher diverged from `ca.DNSNameMatchesSuffixes` | MED | DUP-005 | est/auth.go:246, ca/name_policy.go, acme/identifier.go:28 | EST calls the shared matcher after its wildcard reject; export one normaliser | S | NO | code |
| HB-03 | Remaining unbounded request bodies (20 sites) and parallel JSON writers | MED | P-02 rest, P-04 | authz_custom_roles_handlers.go, handlers_tenants.go, handlers_users.go, handlers_pqc_waves.go, handlers_spiffe.go, nhi_identity.go, pqc_wave_execute.go, spiffe_workload.go, handlers_renewal_execute.go | Use `decodeJSONBody` from A2; replace `writeBadRequestJSON` | M | NO | code |
| HB-04 | Single role store, shared JWT claim validation, role-map error | MED | DUP-004, DUP-007, EH-007, EH-008 | server.go, handlers.go, auth_role_map.go, auth_hs256.go, auth_jwks.go, new auth_claims.go | Build custom role store once; `validateClaims` shared by HS256 and JWKS; fail startup on store error in role-map validation; reject non-string tenant claim | M | NO | code+security |
| HB-05 | ACME ECDSA JWK migration off deprecated API | MED | SA1019 | acme/jws.go:214, store_sqlite.go:242 (+tests) | `ecdsa.ParseUncompressedPublicKey` / `Bytes()`; keep an explicit off-curve JWK rejection test | S | NO | security |
| HB-06 | Bool env idioms and env.example gaps | MED | P-05, P-06, CX-003 | env_helpers.go, auth_config.go, agent_attestation.go, handlers_integrations.go, cmd/kryptkeeper/tls.go, acme/eab.go, keystore/fips.go, certmanager/connector.go, env.example | One `envBool`; document behavior change for `1`; script that diffs code env names against env.example | M | NO | code |
| HB-07 | PQC countdown empty on store error | MED | EH-006 | handlers_pqc_countdown.go:161,166 | Log and return `degraded:true` or 503 | S | NO | code |
| HB-09 | Unsupported issuer connector types (digicert/est/scep/wstep) | MED | DEAD-004 | handlers_connectors.go, UI connector type list, docs/ROADMAP.md | Listing already reports health "unknown" with a reason (honest), so not a blocker. Reject unsupported `type` at create with 400 and label roadmap; wire only as feature work. Verify create path first | S | CONFIRMED (inert) | code+docs |
| HB-08 | `main()` decomposition | MED | CX-001 (structure) | cmd/kryptkeeper/main.go + new files | Extract `buildKeystore/buildCAEngine/resolveDefaultCA/startSchedulers/startCTMonitor` returning errors | L | NO | code |

Wave B file sets are disjoint from each other except HB-03 and HB-04 sharing none; HB-06 touches handlers_integrations.go (A3) so it must follow Wave A.

### Wave C: later (v0.10 or opportunistic)

| ID | Title | Sev | Source | Fix | Eff | Route |
|---|---|---|---|---|---|---|
| LC-01 | Typed Role/Permission/Status (14 prod literals, 4 allowlists) | HIGH (structural) | TS-001/002/003 | `type Role string` + consts + one permission registry; PendingStatus type; start in a dedicated PR before any other authz change | L | code |
| LC-02 | Decisions: wire or delete CT findings API, agent keystore/SSH discovery, sshkeys inventory, ThresholdEvaluator, AD enrollment | MED | DEAD-005..009 | Owner decision per feature; each has green tests masking the gap | M-L | code |
| LC-03 | Dead code cleanup PR (about 250 lines) | LOW | DEAD-010..013, 015, EH-009, S-02, S-03, S-04 | CRL dead slice (generator.go:79-85, live harness shows CRL uses `toRevocationEntries`), duplicate `*StoreFromEnv`, ~20 dead funcs, unused test helpers, `index.css.bak`, vault.go import hack | M | code |
| LC-04 | Tech-stack docs and validator | MED | P-11 | Dependency table in TECH_STACK.md, justify two pkcs7 libs, teach validator the phase-3 path | S | docs |
| LC-05 | Single TTL/replay cache | MED | DUP-003 | `internal/ttlcache` with explicit FullPolicy. Downgraded: CMP records only authenticated messages (cmp/server.go:134), so a flusher needs valid credentials | M | code |
| LC-06 | Provider-level dedupe | MED | CX-004, CX-005, DUP-004 (FromEnv triplets), DUP-006 | Dialect-parameterized `upsertScanResults`, `riskRule` table, `internal/agentproto` | L | code |
| LC-07 | Big-function refactors | MED/LOW | CX-003, CX-006, CX-007, CX-008, CX-009 | Split per concern; keep check ordering in ACME revoke with a pinning test | L | code |
| LC-08 | SAML naming and misc hygiene | MED/LOW | P-07, P-09, P-10, TS-007, TS-008, TS-009, DUP-008, DUP-009 | Rename `checkSAMLResponseFreshness` to `admitSAMLResponse`; inject renewal tracker; explicit `"strict": true`; param validation at POST | M | code |
| LC-09 | UI health | LOW | CX-010, TS-004, TS-005, DUP UI, S-06, EH-010, DEAD-014 | Split 900-1950 line pages, derive types from generated schemas, `usePagedQuery`, shared timeline component | L | code |
| LC-10 | Docs truth | LOW | P-10 | Update CLAUDE.md package count (36 vs 52), drop process-narration comments | S | docs |

Not actionable: SA4023 main.go:134 (build-tag false positive; add `//lint:ignore` or run staticcheck with `-tags pkcs11`).

## Sequencing summary

1. Wave A (6 agents, one day wall clock), merge on green CI, re-run live probes for FB-03, FB-10, FB-11 (security-proven live).
2. Re-run `/review-code --review` scoped to the Wave A files.
3. Release v0.9.0 candidate. Wave B before or right after tagging per owner preference.
