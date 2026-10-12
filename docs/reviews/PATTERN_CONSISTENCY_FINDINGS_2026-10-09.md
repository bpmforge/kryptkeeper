# Pattern Consistency Findings -- 2026-10-09

Scope: Go hub (`internal/`, `cmd/`) + UI at main 6062c62 (after the FG-1..FG-14 merges). Read-only review.
Method: grep counts plus targeted reads. Test files excluded from counts unless noted.
Module key for synthesizer = package directory. Schema: agents/code-review/FINDINGS_SCHEMA.md (ID, severity, module, confidence, fix, effort).

## Scores (1-10)

| Dimension | Score | Why |
|---|---|---|
| Pattern consistency | 6 | Response/error helpers and `AuthenticatePrincipalDetails` are the strong norm; body limits, env parsing and JSON writers have drifted |
| Naming | 8 | 174 validate/check/verify funcs sampled, one clear misnomer |
| Comment accuracy | 7 | Ticket narration is house style and mostly accurate; one stale security comment, a few process-narration blocks |
| Tech-stack compliance | 4 | 12 Go and 11 UI direct deps absent from TECH_STACK.md; validator passes vacuously |

## Baseline (established idioms)

- Auth: `auth.AuthenticatePrincipalDetails(r, now)` = 110 call sites in 57 files in `internal/bootstrap`; legacy `AuthenticatePrincipal(r` = 16 in 12. Role string checks inline in handlers: none. Conforming.
- Errors: `writeBadRequest/Forbidden/NotFound/Conflict/...` -> `writeErrorEnvelope` (`internal/bootstrap/response.go:31-72`), which also honours the problem+json toggle. Exemplars: `handlers_cas.go` (11 helper uses), `handlers_templates.go`.
- Audit: `emitAuditEvent(...)` = 774 uses, `emitAuditEventDetail` = 48. Single idiom, no outliers.
- Body limit: `json.NewDecoder(http.MaxBytesReader(w, r.Body, N))` = 60 uses. Exemplars: `handlers_keys.go:76,176,216`, `handlers_scep_challenges.go:84`, `handlers_pending_actions.go:71` (with `*http.MaxBytesError` -> 413).
- Env bool: `envBool` / `envBoolDefault` (`env_helpers.go:42,47`) accept `true` (case-insensitive) or `1`.

## Findings

### P-01 [MEDIUM] Stale comment: claims ratelimit.clientIP has no trust check
- File: `internal/bootstrap/auth_rate_limit.go:159-164`; module `internal/bootstrap`; confidence 95.
- Snippet: `"honour X-Forwarded-For unconditionally, with no trust check despite a comment claiming otherwise"`
- Reality: `internal/ratelimit/ratelimit.go:82-102` gates XFF on `APP_TRUSTED_PROXY_CIDRS` (own `trustedProxyCIDRs` at `:157`). The W6-11 follow-up it points at already landed. A reader of the security-sensitive file will believe the protocol limiters are spoofable, or "re-fix" it.
- Fix: replace with a one-line pointer: "internal/ratelimit has its own CIDR-gated clientIP keyed on X-Forwarded-For; keep the two in step". Effort: S.

### P-02 [MEDIUM] Request bodies decoded with no size limit (25 sites, 12 files), including pre-auth routes
- Outliers (no `MaxBytesReader` anywhere in file): `handlers_auth.go:68,177,354` (login, refresh: pre-auth), `handlers_agents.go:712,772,793` (agent register is unauthenticated until gate passes), `scim.go:164,380`, `authz_custom_roles_handlers.go:121,164,210`, `handlers_tenants.go:192,228,254`, `handlers_users.go:82,133`, `handlers_evidence.go`, `handlers_pqc_waves.go`, `handlers_spiffe.go`, `nhi_identity.go`, `pqc_wave_execute.go`, `spiffe_workload.go`.
- Snippet: `json.NewDecoder(r.Body).Decode(&req)` (`handlers_auth.go:68`).
- Pattern violated: 60 other sites wrap with `MaxBytesReader` (`handlers_keys.go:76`, `handlers_pending_actions.go:71`). No global body-limit middleware exists (grep of `internal/bootstrap`, `server.go` sets only Read(Header)Timeout 5s/15s).
- Fix: one `decodeJSONBody(w, r, max, &v)` helper next to `response.go` that does MaxBytesReader + error mapping (413 vs 400); migrate the 25 sites. Mitigated only by the 15s ReadTimeout. Effort: M.

### P-03 [MEDIUM] Agent handlers bypass the error envelope and echo internal error text
- File: `internal/bootstrap/handlers_agents.go:713-754` (17 raw `http.Error`), `handlers_notifications.go` (2).
- Snippet (`:722`): `http.Error(w, err.Error(), http.StatusForbidden)` from `enrollmentGate.Check`.
- Violates: `writeForbidden` / `writeBadRequest` (`handlers_cas.go`, `handlers_templates.go`); callers get text/plain instead of the JSON/problem+json envelope the UI and openapi.yaml describe. `err.Error()` surfaces gate internals to an unauthenticated caller.
- Not flagged: `est/`, `scep/`, `wstep/`, `xcep/`, `cmp/` use `http.Error` (33 sites) because their wire protocols are not JSON.
- Also `response.go:33` `writeMethodNotAllowed` itself uses `http.Error` (text/plain) while every sibling helper uses the envelope.
- Fix: switch to helpers; map gate errors to a fixed message. Effort: S.

### P-04 [MEDIUM] Parallel JSON/error writers that skip the problem+json toggle
- `handlers_renewal_execute.go:182` `writeBadRequestJSON` duplicates `writeBadRequest` but hand-builds `{"error":"bad_request",...}` and ignores `shouldUseProblemJSON()` (`response.go`); `:186` `writeJSONStatus`; `handlers_pqc_waves.go:291` `writeJSONData` ({"data":...} wrapper); `scim.go:98,106` (legit: SCIM schema).
- 40 raw `w.WriteHeader(http.StatusBadRequest|Forbidden|...)` in 5 files: `handlers_certificates.go` 17, `handlers_templates.go` 10, `handlers_cas.go` 7, `handlers_approvals.go` 4, `handlers_keys.go` 2; ~150 inline `json.NewEncoder(w).Encode`.
- Fix: delete `writeBadRequestJSON`; add one `writeJSON(w, status, v)` in `response.go`. Effort: M (mechanical).

### P-05 [MEDIUM] Boolean env parsing: 5 idioms, behaviour differs on `1`/case
- `envBool` (`env_helpers.go:42`) == `envFlagTrue` (`auth_config.go:376`): byte-identical duplicate (`envFlagTrue` used 2x vs `envBool` 9x). `auth_config.go:141,151,155,186,207` inline the same expression a fifth time.
- `"true"`-only (a value of `1` is silently ignored): `agent_attestation.go:55` (KRYPTKEEPER_AGENT_OPEN_REGISTRATION), `handlers_integrations.go:22` (SCEP_ENABLED), `cmd/kryptkeeper/tls.go:59,62,136` (TLS_DISABLE, TLS_SELF_ISSUE, REQUEST_CLIENT_CERT), `egress/egress.go:57`, `acme/eab.go:156` (EAB_REQUIRED), `keystore/fips.go:40`, `certmanager/connector.go:79` (K8S_SKIP_VERIFY).
- Case-sensitive: `cmd/kryptkeeper/main.go:213` `os.Getenv("KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT") != "true"`.
- Inverted-default: `key_dual_control.go:97` (only literal `false` disables), `delivery_plugins.go:52` (only `off` disables).
- Impact: `APP_ACME_EAB_REQUIRED=1` leaves EAB off (fails open) while `KRYPTKEEPER_DISABLE_BOOTSTRAP_TOKEN=1` works. Operators cannot predict which spelling a flag takes.
- Fix: one exported `envutil`-style helper (feature-sliced: put in the package that owns config, not a `util/`), accepting true/1/yes; delete `envFlagTrue`. Effort: S-M.

### P-06 [MEDIUM] Env vars missing from env.example / docs
- 245 distinct `KRYPTKEEPER_*|APP_*` names in Go; 86 absent from `env.example`; ~37 of those appear in no doc/README/deploy/chart at all: `APP_SAML_*` (8), `APP_OIDC_*` (8), `APP_SSE_*` (4), all `APP_*_DB_DSN` for config/connectors/findings/ha-lock/inventory/notification-silence/renewal-cooldown/scim/ssh-certs/targets, `APP_SCIM_DEFAULT_ROLE`, `KRYPTKEEPER_KEYGEN_CA_MIN_RSA_BITS`, `KRYPTKEEPER_CMP_ALLOWED_DNS_SUFFIXES`, `KRYPTKEEPER_ANOMALY_NOTIFY_TARGET`, `KRYPTKEEPER_MESH_K8S_{TOKEN,CA_CERT_FILE}`.
- Added by today's FG branches, in docs but not `env.example`: `APP_TRUSTED_PROXY_CIDRS`, `KRYPTKEEPER_AGENT_CREDENTIALS_FILE`, `KRYPTKEEPER_CMP_ALLOWED_DNS_SUFFIXES` (not even in docs), `KRYPTKEEPER_K8S_CA_FILE`, `KRYPTKEEPER_KEY_DUAL_CONTROL`, `KRYPTKEEPER_MCP_HTTP_ADDR`.
- Security-relevant omission: `APP_TRUSTED_PROXY_CIDRS` default-empty means every deployment behind a proxy rate-limits on the proxy IP unless the operator finds this var.
- Fix: add a `scripts/` lint that diffs code env names vs `env.example`; backfill. Effort: M.

### P-07 [LOW] Package-level mutable state / singletons contrary to "no new global state"
- `internal/bootstrap/renewal_retry.go:30` `renewalRetryState = &renewalRetryTracker{attempts: map..., deadLetters: map...}` (mutable maps, process singleton).
- `internal/bootstrap/agent_store_db.go:650` `fallbackAgentStoreOnce = new(sync.Once)` + `fallbackAgentStore` (lazy singleton; comment says it is a pointer so tests can swap it).
- Swappable test seams as `var f = func...`: `discovery_db_provider.go:377,450,460`, `handlers_byok.go:46`, `k8s_discovery.go:33`; `*ProviderWarnf = log.Printf` x4 (`notification_provider.go:21`, `certs_summary_provider.go:16`, `discovery_provider.go:24`, `dashboard_action_provider.go:21`, `audit_provider.go:23`).
- Pre-existing singleton: `metrics/metrics.go:70` `Default`; package http clients `keystore/cloudkms_gcp.go:302`, `cloudkms_azure.go:473`.
- Not verified which were introduced today (no blame run); none of the FG merges' diffs obviously add one. Confidence 75.
- Fix: inject tracker/store via the scheduler constructor. Effort: M.

### P-08 [LOW] Divergent duplicate of the trusted-proxy logic
- `bootstrap/auth_rate_limit.go:213` and `ratelimit/ratelimit.go:157` both define `trustedProxyCIDRs`; `clientIP` trusts X-Real-IP in one and the leftmost X-Forwarded-For in the other. The duplication is acknowledged in `ratelimit.go:104-108`. Leftmost-XFF is client-controlled when the trusted proxy appends rather than overwrites; route to /security. Confidence 80.
- Fix: one shared `internal/ratelimit` export consumed by bootstrap (bootstrap already imports ratelimit-adjacent code? verify no cycle first: comment says neither imports the other). Effort: M.

### P-09 [MEDIUM] Naming: `check*` that mutates
- `internal/bootstrap/auth_saml_guard.go:148` `checkSAMLResponseFreshness` calls `g.consumeRequest` (single-use) and `g.acceptAssertion` (records ID). Calling it twice fails the second time; a name promising a pure check invites a retry/log wrapper that locks the user out.
- Sibling pure checks return `error` (`auth_hs256.go:110 checkJWTNotBefore`). This returns a bare `bool`.
- Fix: rename `admitSAMLResponse` (or `consumeSAMLResponse`) and document single-use. Effort: S. Confidence 85.
- Also (LOW, 75): `ca/name_policy.go:112` `NamePolicy.Check` returns `*PolicyViolation` while `ca/policy_engine.go:225` `PolicyEngine.Check` and `keystore/keygen_policy.go:126` return `error`.

### P-10 [LOW] Comment accuracy / narration
- `CLAUDE.md` "36 packages ok as of 2026-09-10": `go list ./...` now lists 52. Confidence 80.
- `auth_rate_limit.go:49-58` narrates the drafting process ("A first draft swept the ENTIRE map...") rather than the constraint; keep the measured 470x figure, drop the draft story.
- `adsync/ldap_client.go:16-21` "shipped with a stub only, because the dependency was unapproved" is history, not a constraint.
- `acme/server.go:914-917` documents `bootstrap.caCertificateProvider.publicKeyBits` as "a stub that always returns 0": accurate, but see ANTI_SLOP S-01 -- the comment is papering over a stub rather than the stub being fixed.
- Verified accurate (no finding): `ratelimit.go:96-102` nginx claim (nginx.conf only has `/api/`, `/healthz`, `/readyz`, `/`); `auth_rate_limit.go:112` "every allowRateLimit caller passes time.Minute" (9 of 9).

### P-11 [MEDIUM] Tech-stack drift (dimension 9)
- `docs/sdlc/phase-3-design/TECH_STACK.md` (updated 2026-10-08, 521 lines) never names these 12 direct Go deps: `aws-sdk-go-v2`, `aws-sdk-go-v2/service/kms`, `beevik/etree`, `go-pdf/fpdf`, `jcmturner/goidentity/v6`, `mark3labs/mcp-go`, `russellhaering/gosaml2`, `russellhaering/goxmldsig`, `smallstep/pkcs7`, `go.mozilla.org/pkcs7`, `go-pkcs12`, `sdk/delivery-go` (25 direct total). UI: `@base-ui/react`, `@fontsource-variable/geist`, `@radix-ui/react-dialog`, `clsx`, `cmdk`, `next-themes`, `react-dom`, `react-router-dom`, `sonner`, `tailwind-merge`, `tw-animate-css` (15 total).
- Two PKCS#7 libraries: `go.mozilla.org/pkcs7` (`connectors/est_client.go:19`) vs `smallstep/pkcs7` (`connectors/scep_client.go:26`, `scep/server.go:24`). Two headless UI primitives: `@base-ui/react` and `@radix-ui/react-dialog`.
- Validator run: `~/.claude/scripts/validators/validate-tech-stack.sh .` -> "no docs/TECH_STACK.md found -- skipping ... clean -- 0 gaps". It looks only at `docs/TECH_STACK.md`, so the gate passes vacuously here; either symlink or teach it the phase-3 path.
- Fix: add a dependency-inventory table (they are in `docs/THIRD_PARTY_LICENSES.md` already); justify the second pkcs7. Effort: S.

## Counts

Total 11 findings: 0 CRITICAL, 0 HIGH, 8 MEDIUM (P-01..P-06, P-09, P-11), 3 LOW (P-07, P-08, P-10).
