# Duplication Findings — Kryptkeeper — 2026-10-09

Agent: Duplication Detector. Base: main 6062c62. Read-only review.
Method: parsed jscpd reports (Go 20 clones/0.54%, UI 22 clones/1.23%), then grep + deep read of the
security-fix hot spots (replay/TTL caches, egress guards, DNS suffix matchers, client-IP/rate limiters,
FromEnv constructors). Tool budget was capped, so jscpd clones were triaged by location/size, not read line by line.

**Duplication score: 6/10.** Token-level clone rate is low (good), but the parallel security fixes produced
real *logic* duplication with two already-diverged security checks (DUP-001, DUP-002). Several of the
copies document themselves as "duplicated rather than shared" because of ticket write-scope.

Counts: HIGH 2, MEDIUM 4, LOW 3 (9 findings; confidence >= 75 only).

## Divergent security-check copies (explicit)

1. **Client-IP derivation** `internal/ratelimit/ratelimit.go:110` vs `internal/bootstrap/auth_rate_limit.go:165` (DUP-001).
2. **Dial-time SSRF IP deny-list** `internal/acme/http01.go:27` vs `internal/egress/egress.go:68` (DUP-002).
3. **DNS suffix matcher** `internal/est/auth.go:246` vs `internal/ca/name_policy.go:78` (DUP-005, fail-closed divergence, so MEDIUM).

## Findings

### DUP-001 [HIGH] Two clientIP implementations that trust different headers
module: internal/ratelimit + internal/bootstrap | confidence 90 | effort S-M
- A: `internal/ratelimit/ratelimit.go:110-118` — on a trusted-proxy peer, takes `strings.SplitN(r.Header.Get("X-Forwarded-For"), ",", 2)[0]` (LEFTMOST XFF entry).
- B: `internal/bootstrap/auth_rate_limit.go:165-172` — on a trusted peer takes `X-Real-IP`; its doc comment states XFF is "deliberately NOT honoured ... raw, unverified client input".
- Also duplicated verbatim (3 functions each, ~45 lines): `normalizeIP`, `trustedProxyPeer`, `trustedProxyCIDRs` (jscpd clones auth_rate_limit.go:178 / ratelimit.go:124 [27 lines] and :213 / :157 [17 lines]). ratelimit.go's comment admits "duplicated from internal/bootstrap rather than shared" due to write-scope.
- DIVERGED: bootstrap's own comment (auth_rate_limit.go ~line 160) says ratelimit's clientIP honours XFF "unconditionally, with no trust check" — that is now stale (A has the trust check), but A still reads the leftmost XFF value. Behind a proxy that appends to XFF (nginx `$proxy_add_x_forwarded_for`), the leftmost entry is attacker-supplied, so a client on a trusted-proxy peer can rotate the bucket key and bypass the ACME/OCSP/CRL/EST/SCEP/CMP limiters (cmd/kryptkeeper/main.go:537-544). B's choice (header the proxy overwrites) is the safe one.
- Fix: one `internal/clientip` (or export from ratelimit) with `ClientIP(r)`, `TrustedProxyCIDRs` parsed once at startup; both callers use it; pick X-Real-IP (or rightmost-untrusted XFF). Delete the stale comment.

### DUP-002 [HIGH] Dial-guard IP deny-lists: http01 copy is weaker than internal/egress
module: internal/acme + internal/egress | confidence 85 | effort S
- A: `internal/egress/egress.go:68-90` `Policy.checkIP` — unmaps, unwraps NAT64 (`64:ff9b::/96`), blocks `0.0.0.0/8`, link-local, multicast, unspecified; loopback and private/CGNAT (`100.64/10`) are policy-gated.
- B: `internal/acme/http01.go:27-39` `refuseInternalAddr`: `ip.IsLoopback() || ip.IsLinkLocalUnicast() || ... IsMulticast() || ip.IsUnspecified()`.
- DIVERGED: B lacks NAT64 unwrapping (e.g. `64:ff9b::7f00:1`, `64:ff9b::a9fe:a9fe` = cloud metadata via a NAT64 gateway) and the `0.0.0.0/8` check. B intentionally allows RFC1918 (internal CA) — egress already models that as `Policy{AllowPrivate: true}`; CGNAT is also allowed by B only by accident of omission.
- Fix: delete `refuseInternalAddr`; build the http-01 dialer from `egress.Policy{AllowPrivate:true}`'s `control` hook (export a `Policy.DialControl()`), keeping `http01CheckRedirect` (its port/scheme rules are protocol-specific). Add a table test shared by both.

### DUP-003 [MEDIUM] Bounded in-memory TTL/replay caches: five independent implementations
module: internal/bootstrap (+cmp, acme) | confidence 85 | effort M
All answer "remember key for TTL, cap total size, single-use or replay-reject":
- `internal/cmp/replay.go:27-75` `replayCache`: map + `order []string` FIFO, evicts oldest even if live (evict-oldest policy).
- `internal/acme/nonce.go:14-76` `NonceService`: map + `order` FIFO, evict-oldest, no TTL at all (size cap only), compaction at `2*size`.
- `internal/bootstrap/auth_saml_guard.go:43-100` `samlGuardState`: two maps, `sweepExpired` O(n) full scan, reject-new when full (`maxPendingSAMLRequests=4096`, `maxSAMLReplayEntries=8192`).
- `internal/bootstrap/auth_oidc_login.go:149-190` `oidcLoginStateStore`: map, O(n) sweep in `putFlow`, reject-new when full (`maxPendingOIDCLogins=4096`); comment explains why eviction would be a cross-user DoS.
- `internal/bootstrap/auth_login_state.go:34,163` `evictLoginBackoffLocked` (cap 10000) and the rate-limit bucket sweep in `auth_rate_limit.go` (budgeted sweep).
- DIVERGED in policy, not a bug per se: full-table behaviour is *evict-oldest* in cmp/acme (attacker flooding can evict live replay entries => replay window reopens for CMP) but *reject-new* in SAML/OIDC. The OIDC comment documents why reject-new is right for single-use login state; the CMP cache's evict-oldest on `len(order) >= max` lets a flooder (any authenticated or even unauthenticated sender if the cache check precedes auth) flush a victim's recorded nonce and replay it within TTL. Worth a targeted check of replay.go's call order in cmp/server.go.
- Fix: one small generic `internal/ttlcache` (`Add(key, expiry) bool`, `Take(key) bool`, explicit `FullPolicy{RejectNew|EvictOldest}`, injected clock) — also removes the three hand-rolled O(n) sweeps. Do not merge NonceService semantics (no TTL) without a decision.

### DUP-004 [MEDIUM] "FromEnv" constructors create several instances of one store
module: internal/bootstrap | confidence 85 | effort S
- `NewCustomRoleStoreFromEnv()` (`authz_custom_roles_handlers.go:23`) is called at `handlers.go:101` (assigned to `auth.roleStore`), `server.go:92` and `server.go:121` (passed to `withWriteAuthorization`). That is 2-3 separate DB handles and 2-3 `CREATE TABLE IF NOT EXISTS custom_roles` runs per process. The store is stateless over SQL (verified: fields are db/postgres/now), so no stale-cache role divergence today, but if anyone adds a cache the write gate and the handlers would silently disagree on role permissions (a privilege-check hazard).
- Same shape elsewhere: ~12 `*FromEnv` provider triplets (`audit_db_provider.go:180/197/224/228`, `discovery_db_provider.go:569/596/613/617`, `dashboard_action_db_provider.go:29/41/53/57`, `certs_summary_db_provider.go:35/64/81/164`): each re-declares `...SQLiteDSNFromEnv` / `...PostgresDSNFromEnv` wrappers around `resolveSQLiteDSNFromEnv` / `resolvePostgresDSNFromEnv`. jscpd clones: audit_db_provider.go:197/180, notification_db_provider.go:18 / notification_provider.go:80, notification_db_provider.go:393/206.
- Fix: construct the role store once in the server wiring and pass it to both `RegisterHandlers` and `withWriteAuthorization` (2 call sites in server.go + 1 in handlers.go -> 1). A `newDBProviderState` call already exists as the template; extend it to own the DSN-resolver pair so per-feature `xxxSQLiteDSNFromEnv` shims go away.

### DUP-005 [MEDIUM] EST suffix matcher vs ca.DNSNameMatchesSuffixes (diverged, fail-closed)
module: internal/est + internal/ca | confidence 80 | effort S
- A (canonical, reused by CMP at `internal/cmp/server.go:226,233`): `internal/ca/name_policy.go:78-96` — lowercases/trims trailing dot, supports bare `x` and `.x` suffixes, wildcard judged by shallowest expansion.
- B: `internal/est/auth.go:246-258` `nameAllowed` — case-sensitive, no trailing-dot normalisation, only `.x`-style suffixes, rejects `*`, hand-checks empty/dotted labels.
- Divergence: EST rejects `Host.Devices.Corp` (case) and `host.devices.corp.` that CMP/templates/ACME-policy accept; and a bare-form suffix (`devices.corp`) configured for EST admits nothing (silent deny) while CMP admits it. Fails closed, so MEDIUM; but the same operator-entered suffix string means different things per protocol.
- Fix: EST calls `ca.DNSNameMatchesSuffixes` after its own `*`/space rejection (keep the wildcard-reject in EST: its CSR names must be literal). ACME `normalizeDNSIdentifier` (`internal/acme/identifier.go:28`) re-normalises case/dot independently of `ca.normalizeDNSName` — export one normaliser.

### DUP-006 [MEDIUM] Agent enrollment helpers duplicated between hub and agent binary
module: internal/bootstrap + cmd/kryptkeeper-agent | confidence 80 | effort M
- jscpd: `internal/bootstrap/handlers_agents.go:421` <-> `cmd/kryptkeeper-agent/main.go:320` (35 lines) and `:460` <-> `:357` (18 lines). Client-side and server-side copies of the same request/response shapes or token logic; any change to the enrollment protocol must be made twice, and they will drift.
- Fix: move the shared wire structs/helpers into `internal/agentproto` (importable by both). Not read in depth (budget); verify the 35-line block is logic and not just struct literals before extracting.

### DUP-007 [LOW] Handler boilerplate in bootstrap (real, low risk)
module: internal/bootstrap | confidence 80 | effort S
- jscpd: handlers_certificates.go:282 <-> handlers_templates.go:119 (28 lines), handlers_cas.go:187 <-> handlers_templates.go:130 (17), handlers_audit.go:72 <-> handlers_templates.go:129 (18); handlers_templates.go is the common member, i.e. a method-check / auth / decode / audit-write skeleton repeated. Extract `decodeJSONOrFail(w, r, &req)` / `requireRoleAndAudit(...)` helpers. Also `auth_hs256.go:20/51` <-> `auth_jwks.go:22/59` (17 + 33 lines): the JWT claim validation (exp/nbf/iss/aud/role mapping) is cloned between HS256 and JWKS verifiers — this one is security-relevant: extract `validateClaims(claims, cfg)` so the two paths cannot diverge. Lift to MEDIUM if a read confirms the 33-line clone is claim validation (not read).

### DUP-008 [LOW] Keystore software/BYOK clones
module: internal/keystore | confidence 80 | effort M
- software.go:759/632 (25), 786/660 (22), 815/716 (28), byok_recover.go:74 <-> software.go:473 (19). Parallel sign/decrypt/wrap-with-version-lookup paths per algorithm. Private-key code: prefer a single `withKey(ctx, id, func(k) error)` accessor over repeated lookup/zeroise blocks so a future zeroisation fix lands once. Keep as LOW only because the copies are in one package and tested; do not rush an unreviewed refactor on crypto code.

### DUP-009 [LOW] Small, mostly acceptable Go clones
- `mcpserver/writetools.go:147<->122` (17), `hubclient.go:110<->51` (20): request-building boilerplate; fold into one `do(method, path, body)` helper.
- `keyinventory/azure.go:41 <-> gcp.go:46` (13) and `managed_target_store.go:342<->268` (13): ACCEPT (distinct providers / SQL variants).

## jscpd UI triage (22 clones)
- Tests (13 clones: settings-evidence/siem, discovery-*, demo-fixtures/pqc, command-palette x3, IssueWizard x5, IssuanceVelocity): ACCEPT/LOW. Shared render+mock setup; extract a `renderWithProviders` / settings-page fixture only when next touched.
- Pages (9 clones): real but UI-only.
  - **CryptoPosture.tsx:285/751/755 <-> ExpiryTimeline.tsx:95/314/315 (28 + 44 + 72 lines)** — the largest clone in the repo; whole chart/table section copied. MEDIUM-effort extract to a shared component (likely a timeline/bucket table). Severity LOW (no security impact), best ROI in the UI.
  - Keys.tsx (431/461/466/602/631/685, five self-clones 13-22 lines), Tenants.tsx 203/255 (28), Users.tsx 269/308 (21), Alerts.tsx 467/876, Audit.tsx<->History.tsx 142/323: in-file repeated modal/form/row blocks; extract row/modal subcomponents.

## Churn correlation
Not run (jscpd report and the call cap were prioritised; worktree `git log` window of 30 days is dominated by today's fix wave, so churn would point at auth_*.go and ratelimit regardless). Recommend DUP-001/002/003 first precisely because these files are changing now.

## Self-check (micro-loop)
Criterion: every finding names >=2 locations with file:line and a specific fix; divergences on security checks flagged. Met for DUP-001..005; DUP-006..009 rely on jscpd locations only and are labelled as not read in depth.
