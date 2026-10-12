# Kryptkeeper — Phase 4 Workstream Tracker

**Date:** 2026-04-06  
**Owner:** SDLC orchestration

---

## 1. Workstream Board

| ID | Workstream | Scope | Complexity | Status |
|---|---|---|---|---|
| WS-01 | Contract Foundation | Request IDs, RFC7807, pagination envelope, auth middleware baseline | M | DONE |
| WS-02 | Identity & Access | login/refresh, API keys, RBAC enforcement matrix | L | DONE |
| WS-03 | Audit Integrity | append-only write path, denial/success logging, query endpoint | M | DONE |
| WS-04 | Core PKI APIs | CAs, templates, cert issue/renew/revoke/status | L | DONE |
| WS-05 | Protocol Surfaces | ACME/EST/SCEP enrollment + OCSP/CRL status | L | DONE |
| WS-06 | Discovery & Inventory | scan orchestration APIs, endpoint mapping, risk updates | L | DONE |
| WS-07 | Notifications & Ownership | thresholds, routing, delivery logging | M | DONE |
| WS-08 | Dashboard Critical Flows | certificate lifecycle, inventory/risk, alert actions | M | DONE |
| WS-09 | Container Baseline | Dockerfiles, compose profiles, hardening controls | M | DONE |
| WS-10 | CI/CD Baseline | PR/main/release workflows, scan/sign/SBOM gates | M | DONE |

---

## 2. Dependency Map

```mermaid
graph LR
    WS01 --> WS02
    WS02 --> WS03
    WS03 --> WS04
    WS04 --> WS05
    WS04 --> WS06
    WS06 --> WS07
    WS05 --> WS08
    WS07 --> WS08
    WS09 --> WS10
    WS10 --> WS08
```

---

## 3. Definition of Done (Per Workstream)

Each workstream is DONE only if all are true:

1. Code merged and lint/test pass
2. FR traceability updated
3. API contract unchanged or docs updated
4. Security-sensitive checks complete for touched surface
5. Documentation updated (`ARCHITECTURE.md` / API docs / onboarding as needed)

---

## 4. Initial Expert Findings to Apply

### From API review
- Resolve RBAC role model mismatch before WS-02
- Fix API key semantics ambiguity before WS-02
- Align audit identifier type before WS-03

### From DBA migration review
- Execute migration waves in strict order (W1→W7)
- enforce reversible up/down scripts for both Postgres and SQLite

### From test strategy
- Implement top 10 P0 tests first (issuance, revocation propagation, RBAC, audit)

### From container/CI planning
- non-root + read-only filesystem hardening
- scan/sign/SBOM/provenance gates required for main/release pipelines
- delivery manifests created:
  - `phase-4-implementation/MIGRATION_MANIFEST.md`
  - `phase-4-implementation/CICD_WORKFLOW_MANIFEST.md`
  - `phase-4-implementation/BLOCKING_DECISIONS.md` (approved)

---

## 5. Risk Register (Phase 4 Execution)

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Contract drift between implementation and API_DESIGN.md | Medium | High | Contract checks in PR + API review signoff |
| RBAC model ambiguity causes rework | High | High | Resolve model before WS-02 code starts |
| Audit schema mismatch discovered late | Medium | High | Lock schema decisions before WS-03 |
| Protocol conformance failures near release | Medium | High | Protocol smoke tests in PR gate, full suite on release |
| Migration incompatibility across Postgres/SQLite | Medium | High | Dual-engine CI migration tests every wave |

---

## 6. Progress Summary

- Completed: kickoff planning and expert strategy delegation
- Completed: WS-01 and WS-02 incremental slices (contracts + implementation + verification)
- Completed: migration SQL skeletons (W1..W7, PG+SQLite) and initial `.github/workflows/` YAML skeletons
- Completed: W1 foundations + identity migrations implemented (PG + SQLite)
- Completed: `ci-pr.yml` upgraded from placeholder to executable baseline checks
- Completed: W2 templates/CA/certificates migrations implemented (PG + SQLite)
- Completed: `ci-main.yml` upgraded from placeholder to executable baseline checks
- Completed: W3 discovery/endpoints migrations implemented (PG + SQLite)
- Completed: W4 audit append-only migrations implemented (PG + SQLite)
- Completed: W5 P0 index migrations implemented (PG + SQLite)
- Completed: release/promotion/rollback workflow files upgraded to executable baselines
- Completed: W6 engine-specific performance migrations implemented (PG + SQLite)
- Completed: W7 deterministic CI seed migrations implemented (PG + SQLite)
- Completed: nightly scale/protocol workflow upgraded to executable baseline
- Verified: SQLite full migration chain W1→W7 up/down passes with append-only audit behavior intact
- Completed: deployment helper scripts implemented (`scripts/deploy/by-digest.sh`, `scripts/deploy/smoke.sh`)
- Completed: promote/rollback workflows wired to env-specific deploy/smoke configuration secrets
- Completed: release workflow now performs real buildx multi-arch build, digest capture, SBOM, and cosign signing
- Completed: promote/rollback workflows now verify registry digest existence and cosign signature before deploy
- Completed: root Dockerfile and .dockerignore added for release image build path
- Completed: P0 test harness bootstrap added (`scripts/test/run.sh` + `tests/*/run.sh`)
- Completed: Dockerfile upgraded to dual-mode build (`BUILD_MODE=placeholder|real`) with non-root distroless runtime and healthcheck
- Completed: protocol/integration suites upgraded to concrete checks (migration integrity, sqlite W1..W7 smoke, workflow YAML parse)
- Verified: `scripts/test/run.sh --suite protocol --suite integration --suite smoke` passes in current repo state
- Completed: Go bootstrap entrypoint added (`go.mod`, `cmd/kryptkeeper/main.go`) for real-mode container builds
- Completed: CI smoke harness gates added to PR/main workflows (`Runtime smoke (test harness)`)
- Completed: bootstrap endpoint contract matrix documented in `BOOTSTRAP_CONTRACT_MATRIX.md`
- Completed: minimal `/api/v1/meta` contract documented in `API_V1_MINIMAL_CONTRACT.md`
- Completed: bootstrap app now serves `/api/v1/meta` with smoke assertions in local mode
- Completed: first auth-protected endpoint contract documented in `AUTH_V1_MINIMAL_CONTRACT.md`
- Completed: bootstrap app now serves `/api/v1/authz-check` with runtime smoke assertions (401/200/405)
- Completed: JWT transition contract documented in `AUTH_JWT_TRANSITION_CONTRACT.md`
- Completed: `/api/v1/authz-check` now supports `AUTH_MODE=jwt` with HS256 validation (`sub`, `exp`, optional `APP_JWT_ISSUER`/`APP_JWT_AUDIENCE`)
- Completed: CI runtime smoke executes auth-mode matrix (bootstrap + jwt) in local mode
- Completed: OIDC/JWKS contract documented in `AUTH_OIDC_JWKS_CONTRACT.md`
- Completed: `/api/v1/authz-check` now supports `AUTH_MODE=oidc` with RS256 + JWKS (`APP_OIDC_JWKS_JSON`, optional `APP_OIDC_ISSUER`/`APP_OIDC_AUDIENCE`)
- Completed: CI runtime smoke executes auth-mode matrix (bootstrap + jwt + oidc) in local mode
- Completed: managed OIDC discovery contract documented in `AUTH_OIDC_DISCOVERY_CONTRACT.md`
- Completed: `AUTH_MODE=oidc` now supports managed discovery/JWKS refresh path (`APP_OIDC_DISCOVERY_URL` or issuer-derived discovery URL)
- Completed: local smoke supports optional OIDC discovery/JWKS rotation checks (tooling-dependent, skip-safe)
- Completed: OIDC discovery/JWKS rotation runbook documented in `docs/ops/OIDC_JWKS_RUNBOOK.md`
- Completed: first protected resource contract documented in `API_V1_PROTECTED_RESOURCE_CONTRACT.md`
- Completed: first protected endpoint implemented (`GET /api/v1/protected/ping`) with auth-mode smoke assertions
- Completed: second protected resource contract documented in `API_V1_PROTECTED_WHOAMI_CONTRACT.md`
- Completed: second protected endpoint implemented (`GET /api/v1/protected/whoami`) with auth-mode smoke assertions
- Completed: CI runtime smoke stabilized to single harness entrypoint while preserving check-name stability
- Completed: third protected resource contract documented in `API_V1_PROTECTED_CONFIG_CONTRACT.md`
- Completed: third protected endpoint implemented (`GET /api/v1/protected/config`) with auth-mode smoke assertions
- Completed: workflow hardening report updated with protected endpoint coverage (ping + whoami + config)
- Completed: auth mode handling now fails closed for unknown `AUTH_MODE` values
- Completed: 405 contract language aligned across phase-4 API/auth docs (plain text baseline)
- Completed: first persistence-backed protected endpoint contract documented in `API_V1_PROTECTED_CERTS_SUMMARY_CONTRACT.md`
- Completed: first persistence-backed protected endpoint implemented (`GET /api/v1/protected/certs/summary`) via file-backed store
- Completed: smoke assertions added for protected cert summary across bootstrap/jwt/oidc paths
- Completed: internal module split for auth/handler/provider boundaries with behavior-preserving refactor and no contract drift
- Completed: persistence provider abstraction rollout for cert summary path (`source` remains provider-derived; additive provider identifiers allowed)
- Note: this rollout is internal-only for phase-4 wave and does not change endpoint contract fields/status codes
- Completed: auth/handler wiring now split into feature-sliced internal modules (`auth_*`, `handlers_*`, `response.go`)
- Completed: cert summary contract updated to treat provider selection as internal-only while allowing additive `source` values
- Completed: cert summary provider selection factory now supports real DB-backed mode with file-backed default; db mode now supports SQLite and Postgres adapters and returns live DB counts when configured
- Completed: provider wiring tightened to require explicit injection (including certificate provider) with no silent nil fallback or implicit env construction inside handler registration
- Completed: server startup/shutdown extracted into `internal/bootstrap/server.go`
- Completed: handler registration now validates auth/provider injection before wiring routes
- Completed: provider observability logging added for file-backed fallback reasons and db stub mode (internal-only)
- Completed: discovery_enabled semantics aligned to active managed OIDC discovery only (no static JWKS override signal)
- Completed: local smoke now verifies DB-backed cert summary path in sqlite mode (`db-store-sqlite`) and fail-closed `503` behavior for postgres mode with missing DSN
- Completed: Phase 4 FR/NFR traceability tracker added (`FR_TRACEABILITY_TRACKER.md`) and linked to PR gate checklist
- Completed: initial audit query contract documented (`API_V1_AUDIT_CONTRACT.md`) and endpoint implemented (`GET /api/v1/audit`) with file/db providers and fail-closed `503` path
- Completed: runtime smoke now validates `/api/v1/audit` in bootstrap/jwt modes for auth + contract baseline
- Completed: audit append write path instrumentation added for auth/protected/audit list reads with success/denied/failure outcomes, preserving append-only storage contract
- Completed: `/api/v1/audit` now supports initial filter/pagination query parameters (`action`, `actor_type`, `resource_type`, `limit`, `cursor`, `order`) with cursor metadata in responses
- Completed: `/api/v1/audit` filter coverage expanded with `actor_id`, `resource_id`, `trace_id`, `after`, and `before` semantics
- Completed: WS-03 audit integrity slice (append-only writes + deny/success/failure logging + query endpoint/filter coverage) is now functionally in place for bootstrap surfaces
- Completed: WS-04 Core PKI APIs started with first CA listing endpoint slice (`GET /api/v1/cas`) and contract-backed filtering/pagination baseline
- Completed: WS-04 Core PKI APIs extended with CA detail read slice (`GET /api/v1/cas/{id}`) including 404/503 fail-closed behavior
- Completed: WS-04 Core PKI APIs extended with CA chain read slice (`GET /api/v1/cas/{id}/chain`) including json/pem response modes
- Completed: WS-04 Core PKI APIs extended with CA state transition slices (`POST /api/v1/cas/{id}/suspend`, `POST /api/v1/cas/{id}/activate`) including 409 conflict handling
- Completed: WS-04 Core PKI APIs extended with CA mutable update slice (`PATCH /api/v1/cas/{id}`) including immutable field enforcement (`422`)
- Completed: WS-04 Core PKI APIs extended with CA delete slice (`DELETE /api/v1/cas/{id}`) including 422 state validation and 409 active-cert conflict handling
- Completed: WS-04 template baseline started with list/detail read slices (`GET /api/v1/templates`, `GET /api/v1/templates/{id}`)
- Completed: WS-04 template create slice added (`POST /api/v1/templates`) with duplicate name/OID conflict handling (`409`)
- Completed: WS-04 template replace slice added (`PUT /api/v1/templates/{id}`) with `If-Match` revision precondition handling (`412`)
- Completed: WS-04 template mutable update slice added (`PATCH /api/v1/templates/{id}`) with immutable-field rejection (`422`) and invalid-field rejection (`400`)
- Completed: WS-04 template delete slice added (`DELETE /api/v1/templates/{id}`) with issued-certificate conflict handling (`409`)
- Completed: WS-04 template clone slice added (`POST /api/v1/templates/{id}/clone`) with clone-name conflict handling (`409`)
- Completed: WS-04 certificate baseline added (`GET /api/v1/certificates`, `GET /api/v1/certificates/{fingerprint}`) with filter/pagination and ETag conditional-read behavior
- Completed: WS-04 certificate chain + revoke slices added (`GET /api/v1/certificates/{fingerprint}/chain`, `POST /api/v1/certificates/{fingerprint}/revoke`) with 404/409 handling
- Completed: WS-04 certificate issue + renew slices added (`POST /api/v1/certificates`, `POST /api/v1/certificates/{fingerprint}/renew`) with deterministic smoke coverage for create-then-conflict flow
- Completed: WS-04 certificate download + import slices added (`GET /api/v1/certificates/{fingerprint}/download`, `POST /api/v1/certificates/import`) with format validation and duplicate import conflict behavior
- Completed: WS-04 cert handler hardening completed for request-size limits, fail-closed file-store error handling, filename sanitization, and team-scoped authorization checks
- Verified: WS-04 security re-audit reports no remaining CRITICAL/HIGH findings in certificate endpoint scope
- In progress: WS-01 request-correlation slice delivered (`X-Request-ID` middleware with inbound echo, generated fallback, and context propagation) with unit-test coverage
- In progress: WS-02 identity slice delivered with additive login/refresh endpoints and API-key bearer auth routing (`kk_<kid>_<secret>`), while preserving existing bootstrap/jwt/oidc behavior
- In progress: WS-02 API key management slice delivered (`GET/POST /api/v1/api-keys`, `DELETE /api/v1/api-keys/{kid}`) with smoke coverage for bootstrap and jwt modes
- Verified: WS-02 focused security re-audit now reports zero CRITICAL/HIGH findings after auth-path gating and rate-limit hardening
- In progress: WS-01 error-format compatibility slice delivered with opt-in RFC7807 mode (`APP_ERROR_FORMAT=problem|rfc7807`) while retaining legacy JSON default
- Verified: focused WS-01/WS-02 security audit completed for auth/request-correlation/error-format surfaces (`docs/ops/ws-01-ws-02-security-audit-latest.md`), with later re-audit closing prior HIGH bind-exposure concern
- Verified: WS-01/WS-02 focused security re-audit now reports zero CRITICAL/HIGH findings after bind-address hardening (`APP_BIND_ADDR` default loopback in `cmd/kryptkeeper/main.go`, explicit container bind in `docker-compose.yml`)
- In progress: WS-05 protocol-surface baseline delivered with authenticated `GET /api/v1/protocols/status` and bootstrap/jwt smoke assertions
- In progress: WS-05 incremental protocol readiness slice delivered with authenticated `GET /api/v1/protocols/readiness` and bootstrap/jwt smoke assertions
- In progress: WS-05 incremental protocol conformance slice delivered with authenticated `GET /api/v1/protocols/conformance` and bootstrap/jwt smoke assertions
- In progress: WS-05 incremental protocol conformance recheck slice delivered with authenticated `POST /api/v1/protocols/conformance/recheck` and bootstrap/jwt smoke assertions
- In progress: WS-06 discovery baseline delivered with authenticated `GET /api/v1/discovery/summary` and bootstrap/jwt smoke assertions
- In progress: WS-06 incremental discovery inventory slice delivered with authenticated `GET /api/v1/discovery/endpoints` (filter + pagination envelope) and bootstrap/jwt smoke assertions
- In progress: WS-06 incremental discovery scan-jobs slice delivered with authenticated `GET /api/v1/discovery/scan-jobs` (status/target filters + pagination envelope) and bootstrap/jwt smoke assertions
- In progress: WS-06 incremental discovery scan-job cancellation slice delivered with authenticated `POST /api/v1/discovery/scan-jobs/cancel` and bootstrap/jwt smoke assertions
- In progress: WS-06 incremental discovery scan-job requeue slice delivered with authenticated `POST /api/v1/discovery/scan-jobs/requeue` and bootstrap/jwt smoke assertions
- In progress: WS-06 incremental discovery orchestration slice delivered with authenticated `POST /api/v1/discovery/scans` (queued response), discovery-write authorization gate, and bootstrap/jwt smoke assertions
- In progress: WS-07 notifications baseline delivered with authenticated `GET /api/v1/notifications/summary` and bootstrap/jwt smoke assertions
- In progress: WS-07 incremental notifications delivery-log slice delivered with authenticated `GET /api/v1/notifications/deliveries` (status/channel filters + pagination envelope) and bootstrap/jwt smoke assertions
- In progress: WS-07 incremental notifications delivery-ack slice delivered with authenticated `POST /api/v1/notifications/deliveries/ack` and bootstrap/jwt smoke assertions
- In progress: WS-07 incremental notifications delivery-retry slice delivered with authenticated `POST /api/v1/notifications/deliveries/retry` and bootstrap/jwt smoke assertions
- In progress: WS-07 incremental notifications delivery slice delivered with authenticated `POST /api/v1/notifications/test-delivery` (accepted/queued response), notification-write authorization gate, and bootstrap/jwt smoke assertions
- In progress: WS-08 dashboard baseline delivered with authenticated `GET /api/v1/dashboard/summary` aggregate cards and bootstrap/jwt smoke assertions
- In progress: WS-08 incremental dashboard actions slice delivered with authenticated `GET /api/v1/dashboard/actions` prioritized action queue and bootstrap/jwt smoke assertions
- In progress: WS-08 incremental dashboard action-history slice delivered with authenticated `GET /api/v1/dashboard/actions/history` (status/category filters + pagination envelope) and bootstrap/jwt smoke assertions
- In progress: WS-08 incremental dashboard action-ack slice delivered with authenticated `POST /api/v1/dashboard/actions/ack` and bootstrap/jwt smoke assertions
- In progress: WS-08 incremental dashboard action-resolve slice delivered with authenticated `POST /api/v1/dashboard/actions/resolve` and bootstrap/jwt smoke assertions
- Verified: bootstrap smoke now asserts explicit method-guard (`405`) behavior for WS-05/WS-06/WS-07/WS-08 incremental routes (`protocols/readiness`, `protocols/conformance`, `protocols/conformance/recheck`, `discovery/endpoints`, `discovery/scan-jobs`, `discovery/scan-jobs/cancel`, `discovery/scan-jobs/requeue`, `discovery/scans`, `notifications/deliveries`, `notifications/deliveries/ack`, `notifications/deliveries/retry`, `notifications/test-delivery`, `dashboard/actions`, `dashboard/actions/history`, `dashboard/actions/ack`, `dashboard/actions/resolve`)
- Verified: WS-05/WS-06/WS-07/WS-08 baseline handlers now enforce explicit operational-summary authorization (`403` on insufficient role/scope); focused security re-audit reports zero CRITICAL/HIGH findings in this scope
- Verified: WS-09 container baseline hardening re-audit reports zero CRITICAL/HIGH findings in `docker-compose.yml` and `Dockerfile` scope (required bootstrap token env and loopback-only port binding remain enforced)
- Verified: WS-10 CI re-audit now reports zero remaining CRITICAL/HIGH findings after fail-closed hardening in `ci-main` integration/protocol gates (no `go.mod` skip guard, required protocol suite presence, required `*_test.go` file checks)
- Verified: WS-01/WS-02 focused security re-audit reports zero CRITICAL/HIGH findings after runtime bind hardening (`APP_BIND_ADDR` default loopback in binary, explicit container bind + loopback host publish)
- Verified: smoke harness now fails on real assertion errors in local mode execution path; deterministic audit filter assertion updated to seeded fixture (`actor_id=system`, `resource_id=fp-1`)
- Verified: focused security review for WS-05 protocol readiness and WS-06 discovery scan-create slices reports zero CRITICAL/HIGH findings in scope
- Verified: focused security review for WS-07 notification test-delivery slice reports zero CRITICAL/HIGH findings in scope
- Verified: focused security review for WS-08 dashboard actions slice reports zero CRITICAL/HIGH findings in scope
- Verified: focused security review for WS-06 discovery endpoint-inventory list slice reports zero CRITICAL/HIGH findings in scope
- Verified: focused security review for WS-07 notification delivery-log list slice reports zero CRITICAL/HIGH findings in scope
- Verified: focused security review for WS-05 protocol-conformance slice reports zero CRITICAL/HIGH findings in scope
- Verified: focused security review for WS-08 dashboard action-ack slice reports zero CRITICAL/HIGH findings in scope
- Verified: focused security review for WS-06 discovery scan-jobs list slice reports zero CRITICAL/HIGH findings in scope
- Verified: focused security review for WS-07 notification delivery-retry slice reports zero CRITICAL/HIGH findings in scope
- Verified: focused security review for WS-05 protocol-conformance recheck slice reports zero CRITICAL/HIGH findings in scope
- Verified: focused security review for WS-08 dashboard actions-history slice reports zero CRITICAL/HIGH findings in scope
- Verified: focused security review for WS-06 discovery scan-job cancel slice reports zero CRITICAL/HIGH findings in scope
- Verified: focused security review for WS-08 dashboard action-resolve slice reports zero CRITICAL/HIGH findings in scope
- Verified: focused security review for WS-07 notification delivery-ack slice reports zero CRITICAL/HIGH findings in scope
- Verified: focused security review for WS-06 discovery scan-job requeue slice reports zero CRITICAL/HIGH findings in scope
- Completed: WS-05 provider abstraction rollout — `ProtocolProvider` interface with file-backed adapter, replacing direct env-var reads in protocol handlers; handlers now delegate to provider with fail-closed `503` on errors
- Completed: WS-06 provider abstraction rollout — `DiscoveryProvider` interface with file-backed adapter and generic `paginate[T]` helper, replacing hardcoded data and duplicate parse helpers in discovery handlers
- Completed: WS-07 provider abstraction rollout — `NotificationProvider` interface with file-backed adapter, replacing hardcoded delivery data and duplicate parse helpers in notification handlers
- Completed: WS-08 provider abstraction rollout — `DashboardActionProvider` interface with file-backed adapter; dashboard handlers now consume `DiscoveryProvider` and `NotificationProvider` for live summary data instead of env-var reads
- Completed: env helper consolidation — `envBool`, `envBoolDefault`, `envOptionalRFC3339`, `envInt`, `envConformanceState`, `envClampedInt` extracted to shared `env_helpers.go`; duplicates removed from handler files
- Completed: handler registration expanded to accept all 4 new providers via DI with nil-check panic guards
- Verified: all existing unit tests updated for new `RegisterHandlers` signature and passing
- Verified: new unit tests added for all 4 provider file adapters and generic `paginate` helper
- Verified: smoke harness passes with provider-backed handler wiring
- Verified: focused security audit on WS-05/06/07/08 provider layer completed (`docs/ops/ws-05-08-provider-security-audit.md`)
- Completed: HIGH-1 scan_type allowlist + target length cap added to discovery scan create handler
- Completed: HIGH-2 channel allowlist + target/message length caps added to notification test-delivery handler
- Completed: MEDIUM-1 per-field length caps (500 chars) added to all reason/note/message fields across POST handlers
- Completed: MEDIUM-2 `service-account` role added to ops-read allowlist so JWT/OIDC auth modes can access WS-05-08 read endpoints
- Completed: LOW-1 `ReadTimeout`, `WriteTimeout`, `IdleTimeout` added to `http.Server` in `server.go`
- Verified: smoke assertions updated from 403-denied to 200-allowed for JWT service-account on read endpoints
- Verified: zero remaining CRITICAL/HIGH findings in WS-05/06/07/08 provider scope after hardening
- Completed: WS-06 DB-backed adapter rollout — `DiscoveryProvider` SQLite + Postgres stores reading from W3 schema (`scan_jobs`, `endpoints`, `certificate_endpoints`); all 6 operations implemented with parameterized queries
- Completed: W8 migration — `notification_deliveries` table added (SQLite + Postgres) with channel/status constraints, retry tracking, ack fields, and CI seed data
- Completed: WS-07 DB-backed adapter rollout — `NotificationProvider` SQLite + Postgres stores reading from W8 schema; all 5 operations implemented with parameterized queries
- Completed: WS-08 DB-backed adapter rollout — `DashboardActionProvider` SQLite + Postgres stores using `audit_log` as action history source (aggregate queries, no new migration); ack/resolve write to append-only audit_log
- Verified: unit tests for all 3 DB adapter suites (discovery 7 tests, notification 6 tests, dashboard action 4 tests) plus fail-closed behavior
- Verified: all existing tests + smoke harness pass with DB adapter factory wiring
