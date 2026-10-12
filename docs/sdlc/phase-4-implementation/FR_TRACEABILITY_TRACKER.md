# Kryptkeeper — Phase 4 FR/NFR Traceability Tracker

**Status:** Active (Phase 4)

This tracker maps implemented Phase 4 surfaces to requirements and tests so PR gates can verify:

1. requirement coverage,
2. contract alignment,
3. verification evidence.

---

## Traceability Matrix

| Requirement | Surface | Contract Doc | Implementation | Verification |
|---|---|---|---|---|
| FR-090 | `/api/v1/meta` | `API_V1_MINIMAL_CONTRACT.md` | `internal/bootstrap/handlers_meta.go` | `tests/smoke/run.sh` |
| FR-091 | `/api/v1/authz-check` (bootstrap/jwt/oidc) | `AUTH_V1_MINIMAL_CONTRACT.md`, `AUTH_JWT_TRANSITION_CONTRACT.md`, `AUTH_OIDC_JWKS_CONTRACT.md`, `AUTH_OIDC_DISCOVERY_CONTRACT.md` | `internal/bootstrap/handlers_auth.go`, `internal/bootstrap/auth_*.go` | `tests/smoke/run.sh`, `internal/bootstrap/auth_config_test.go` |
| FR-091 (api-key bearer extension) | Bearer `kk_<kid>_<secret>` auth path | `AUTH_API_KEY_BEARER_CONTRACT.md` | `internal/bootstrap/auth.go`, `internal/bootstrap/auth_identity.go`, `internal/bootstrap/auth_config.go` | `tests/smoke/run.sh`, `internal/bootstrap/auth_identity_test.go` |
| FR-091 (identity token issue) | `/api/v1/auth/login` | `API_V1_AUTH_LOGIN_CONTRACT.md` | `internal/bootstrap/handlers_auth.go`, `internal/bootstrap/auth_identity.go` | `tests/smoke/run.sh`, `internal/bootstrap/auth_identity_test.go` |
| FR-091 (identity token refresh) | `/api/v1/auth/refresh` | `API_V1_AUTH_REFRESH_CONTRACT.md` | `internal/bootstrap/handlers_auth.go`, `internal/bootstrap/auth_identity.go` | `tests/smoke/run.sh`, `internal/bootstrap/auth_identity_test.go` |
| FR-091 (api-key management path) | `/api/v1/api-keys` (`GET`, `POST`, `DELETE /{kid}`) | `API_V1_API_KEYS_CONTRACT.md` | `internal/bootstrap/handlers_auth.go`, `internal/bootstrap/auth_identity.go` | `tests/smoke/run.sh` |
| NFR-Traceability (request correlation) | All v1/bootstrap routes (`X-Request-ID` response header) | `API_V1_REQUEST_ID_CONTRACT.md` | `internal/bootstrap/middleware_request_id.go`, `internal/bootstrap/server.go` | `internal/bootstrap/middleware_request_id_test.go` |
| NFR-Contract compatibility (error format) | Shared error helpers (legacy JSON + RFC7807 compat mode) | `API_V1_ERROR_FORMAT_COMPAT_CONTRACT.md` | `internal/bootstrap/response.go` | `internal/bootstrap/response_test.go` |
| FR-092 | `/api/v1/protected/ping` | `API_V1_PROTECTED_RESOURCE_CONTRACT.md` | `internal/bootstrap/handlers_protected_ping.go` | `tests/smoke/run.sh` |
| FR-093 | `/api/v1/protected/whoami` | `API_V1_PROTECTED_WHOAMI_CONTRACT.md` | `internal/bootstrap/handlers_protected_whoami.go` | `tests/smoke/run.sh` |
| FR-094 | `/api/v1/protected/config` | `API_V1_PROTECTED_CONFIG_CONTRACT.md` | `internal/bootstrap/handlers_protected_config.go` | `tests/smoke/run.sh` |
| FR-094 (extension path) | `/api/v1/protected/certs/summary` | `API_V1_PROTECTED_CERTS_SUMMARY_CONTRACT.md` | `internal/bootstrap/handlers_protected_certs_summary.go`, `internal/bootstrap/certs_summary_*` | `tests/smoke/run.sh`, `internal/bootstrap/certs_summary_store_test.go` |
| FR-094 (audit query path) | `/api/v1/audit` | `API_V1_AUDIT_CONTRACT.md` | `internal/bootstrap/handlers_audit.go`, `internal/bootstrap/audit_*` | `tests/smoke/run.sh`, `internal/bootstrap/audit_store_test.go` |
| WS-05 baseline (protocol visibility path) | `/api/v1/protocols/status` | `API_V1_PROTOCOL_STATUS_CONTRACT.md` | `internal/bootstrap/handlers_protocols.go` | `tests/smoke/run.sh` |
| WS-05 incremental (protocol readiness path) | `/api/v1/protocols/readiness` | `API_V1_PROTOCOL_READINESS_CONTRACT.md` | `internal/bootstrap/handlers_protocols.go` | `tests/smoke/run.sh` |
| WS-05 incremental (protocol conformance path) | `/api/v1/protocols/conformance` | `API_V1_PROTOCOL_CONFORMANCE_CONTRACT.md` | `internal/bootstrap/handlers_protocols.go` | `tests/smoke/run.sh` |
| WS-05 incremental (protocol conformance recheck path) | `POST /api/v1/protocols/conformance/recheck` | `API_V1_PROTOCOL_CONFORMANCE_RECHECK_CONTRACT.md` | `internal/bootstrap/handlers_protocols.go`, `internal/bootstrap/authz_ops.go` | `tests/smoke/run.sh` |
| WS-06 baseline (discovery summary path) | `/api/v1/discovery/summary` | `API_V1_DISCOVERY_SUMMARY_CONTRACT.md` | `internal/bootstrap/handlers_discovery.go` | `tests/smoke/run.sh` |
| WS-06 incremental (endpoint inventory path) | `GET /api/v1/discovery/endpoints` | `API_V1_DISCOVERY_ENDPOINTS_LIST_CONTRACT.md` | `internal/bootstrap/handlers_discovery.go` | `tests/smoke/run.sh` |
| WS-06 incremental (scan-jobs listing path) | `GET /api/v1/discovery/scan-jobs` | `API_V1_DISCOVERY_SCAN_JOBS_LIST_CONTRACT.md` | `internal/bootstrap/handlers_discovery.go` | `tests/smoke/run.sh` |
| WS-06 incremental (scan-job cancel path) | `POST /api/v1/discovery/scan-jobs/cancel` | `API_V1_DISCOVERY_SCAN_JOB_CANCEL_CONTRACT.md` | `internal/bootstrap/handlers_discovery.go`, `internal/bootstrap/authz_ops.go` | `tests/smoke/run.sh` |
| WS-06 incremental (scan-job requeue path) | `POST /api/v1/discovery/scan-jobs/requeue` | `API_V1_DISCOVERY_SCAN_JOB_REQUEUE_CONTRACT.md` | `internal/bootstrap/handlers_discovery.go`, `internal/bootstrap/authz_ops.go` | `tests/smoke/run.sh` |
| WS-06 incremental (scan orchestration path) | `POST /api/v1/discovery/scans` | `API_V1_DISCOVERY_SCANS_CREATE_CONTRACT.md` | `internal/bootstrap/handlers_discovery.go`, `internal/bootstrap/authz_ops.go` | `tests/smoke/run.sh` |
| WS-07 baseline (notification summary path) | `/api/v1/notifications/summary` | `API_V1_NOTIFICATIONS_SUMMARY_CONTRACT.md` | `internal/bootstrap/handlers_notifications.go` | `tests/smoke/run.sh` |
| WS-07 incremental (delivery log path) | `GET /api/v1/notifications/deliveries` | `API_V1_NOTIFICATIONS_DELIVERIES_LIST_CONTRACT.md` | `internal/bootstrap/handlers_notifications.go` | `tests/smoke/run.sh` |
| WS-07 incremental (delivery acknowledge path) | `POST /api/v1/notifications/deliveries/ack` | `API_V1_NOTIFICATIONS_DELIVERY_ACK_CONTRACT.md` | `internal/bootstrap/handlers_notifications.go` | `tests/smoke/run.sh` |
| WS-07 incremental (delivery retry path) | `POST /api/v1/notifications/deliveries/retry` | `API_V1_NOTIFICATIONS_DELIVERY_RETRY_CONTRACT.md` | `internal/bootstrap/handlers_notifications.go` | `tests/smoke/run.sh` |
| WS-07 incremental (delivery test path) | `POST /api/v1/notifications/test-delivery` | `API_V1_NOTIFICATIONS_TEST_DELIVERY_CONTRACT.md` | `internal/bootstrap/handlers_notifications.go`, `internal/bootstrap/authz_ops.go` | `tests/smoke/run.sh` |
| WS-08 baseline (dashboard summary path) | `/api/v1/dashboard/summary` | `API_V1_DASHBOARD_SUMMARY_CONTRACT.md` | `internal/bootstrap/handlers_dashboard.go` | `tests/smoke/run.sh` |
| WS-08 incremental (dashboard actions path) | `/api/v1/dashboard/actions` | `API_V1_DASHBOARD_ACTIONS_CONTRACT.md` | `internal/bootstrap/handlers_dashboard.go` | `tests/smoke/run.sh` |
| WS-08 incremental (dashboard actions history path) | `/api/v1/dashboard/actions/history` | `API_V1_DASHBOARD_ACTIONS_HISTORY_CONTRACT.md` | `internal/bootstrap/handlers_dashboard.go` | `tests/smoke/run.sh` |
| WS-08 incremental (dashboard action acknowledge path) | `POST /api/v1/dashboard/actions/ack` | `API_V1_DASHBOARD_ACTION_ACK_CONTRACT.md` | `internal/bootstrap/handlers_dashboard.go`, `internal/bootstrap/authz_ops.go` | `tests/smoke/run.sh` |
| WS-08 incremental (dashboard action resolve path) | `POST /api/v1/dashboard/actions/resolve` | `API_V1_DASHBOARD_ACTION_RESOLVE_CONTRACT.md` | `internal/bootstrap/handlers_dashboard.go`, `internal/bootstrap/authz_ops.go` | `tests/smoke/run.sh` |
| WS-09 baseline (container runtime profile) | Root container runtime baseline (`Dockerfile`, `docker-compose.yml`) | `CONTAINER_BASELINE_CONTRACT.md` | `Dockerfile`, `docker-compose.yml` | `scripts/test/run.sh --suite smoke` |
| WS-10 baseline (harness gates) | PR/main workflow harness coverage (`protocol`, `integration`, `smoke`) + fail-closed required-suite checks | `CI_HARNESS_GATES_CONTRACT.md` | `.github/workflows/ci-pr.yml`, `.github/workflows/ci-main.yml` | `scripts/test/run.sh --suite protocol --suite integration --suite smoke` |
| FR-001 (CA lifecycle read path) | `/api/v1/cas` | `API_V1_CAS_LIST_CONTRACT.md` | `internal/bootstrap/handlers_cas.go`, `internal/bootstrap/ca_*` | `tests/smoke/run.sh`, `internal/bootstrap/ca_store_test.go` |
| FR-001 (CA lifecycle detail read path) | `/api/v1/cas/{id}` | `API_V1_CAS_GET_CONTRACT.md` | `internal/bootstrap/handlers_cas.go`, `internal/bootstrap/ca_*` | `tests/smoke/run.sh`, `internal/bootstrap/ca_store_test.go` |
| FR-001 (CA lifecycle chain read path) | `/api/v1/cas/{id}/chain` | `API_V1_CAS_CHAIN_CONTRACT.md` | `internal/bootstrap/handlers_cas.go`, `internal/bootstrap/ca_*` | `tests/smoke/run.sh`, `internal/bootstrap/ca_store_test.go` |
| FR-001 (CA lifecycle mutable update path) | `/api/v1/cas/{id}` (PATCH) | `API_V1_CAS_PATCH_CONTRACT.md` | `internal/bootstrap/handlers_cas.go`, `internal/bootstrap/ca_*` | `tests/smoke/run.sh`, `internal/bootstrap/ca_store_test.go` |
| FR-002 (CA lifecycle suspend path) | `/api/v1/cas/{id}/suspend` | `API_V1_CAS_SUSPEND_CONTRACT.md` | `internal/bootstrap/handlers_cas.go`, `internal/bootstrap/ca_*` | `tests/smoke/run.sh`, `internal/bootstrap/ca_store_test.go` |
| FR-002 (CA lifecycle activate path) | `/api/v1/cas/{id}/activate` | `API_V1_CAS_ACTIVATE_CONTRACT.md` | `internal/bootstrap/handlers_cas.go`, `internal/bootstrap/ca_*` | `tests/smoke/run.sh`, `internal/bootstrap/ca_store_test.go` |
| FR-002 (CA lifecycle delete path) | `/api/v1/cas/{id}` (DELETE) | `API_V1_CAS_DELETE_CONTRACT.md` | `internal/bootstrap/handlers_cas.go`, `internal/bootstrap/ca_*` | `tests/smoke/run.sh`, `internal/bootstrap/ca_store_test.go` |
| FR-020 (template list path) | `/api/v1/templates` | `API_V1_TEMPLATES_LIST_CONTRACT.md` | `internal/bootstrap/handlers_templates.go`, `internal/bootstrap/template_*` | `tests/smoke/run.sh`, `internal/bootstrap/template_store_test.go` |
| FR-020 (template create path) | `/api/v1/templates` (POST) | `API_V1_TEMPLATES_CREATE_CONTRACT.md` | `internal/bootstrap/handlers_templates.go`, `internal/bootstrap/template_*` | `tests/smoke/run.sh`, `internal/bootstrap/template_store_test.go` |
| FR-020 (template detail path) | `/api/v1/templates/{id}` | `API_V1_TEMPLATES_GET_CONTRACT.md` | `internal/bootstrap/handlers_templates.go`, `internal/bootstrap/template_*` | `tests/smoke/run.sh`, `internal/bootstrap/template_store_test.go` |
| FR-020 (template replace path) | `/api/v1/templates/{id}` (PUT) | `API_V1_TEMPLATES_PUT_CONTRACT.md` | `internal/bootstrap/handlers_templates.go`, `internal/bootstrap/template_*` | `tests/smoke/run.sh`, `internal/bootstrap/template_store_test.go` |
| FR-020 (template mutable update path) | `/api/v1/templates/{id}` (PATCH) | `API_V1_TEMPLATES_PATCH_CONTRACT.md` | `internal/bootstrap/handlers_templates.go`, `internal/bootstrap/template_*` | `tests/smoke/run.sh`, `internal/bootstrap/template_store_test.go` |
| FR-020 (template delete path) | `/api/v1/templates/{id}` (DELETE) | `API_V1_TEMPLATES_DELETE_CONTRACT.md` | `internal/bootstrap/handlers_templates.go`, `internal/bootstrap/template_*` | `tests/smoke/run.sh`, `internal/bootstrap/template_store_test.go` |
| FR-020 (template clone path) | `/api/v1/templates/{id}/clone` | `API_V1_TEMPLATES_CLONE_CONTRACT.md` | `internal/bootstrap/handlers_templates.go`, `internal/bootstrap/template_*` | `tests/smoke/run.sh`, `internal/bootstrap/template_store_test.go` |
| FR-001 (certificate list path) | `/api/v1/certificates` | `API_V1_CERTIFICATES_LIST_CONTRACT.md` | `internal/bootstrap/handlers_certificates.go`, `internal/bootstrap/certificate_*` | `tests/smoke/run.sh`, `internal/bootstrap/certificate_store_test.go` |
| FR-001 (certificate detail path) | `/api/v1/certificates/{fingerprint}` | `API_V1_CERTIFICATES_GET_CONTRACT.md` | `internal/bootstrap/handlers_certificates.go`, `internal/bootstrap/certificate_*` | `tests/smoke/run.sh`, `internal/bootstrap/certificate_store_test.go` |
| FR-001 (certificate chain path) | `/api/v1/certificates/{fingerprint}/chain` | `API_V1_CERTIFICATES_CHAIN_CONTRACT.md` | `internal/bootstrap/handlers_certificates.go`, `internal/bootstrap/certificate_*` | `tests/smoke/run.sh`, `internal/bootstrap/certificate_store_test.go` |
| FR-001 (certificate issue path) | `/api/v1/certificates` (POST) | `API_V1_CERTIFICATES_ISSUE_CONTRACT.md` | `internal/bootstrap/handlers_certificates.go`, `internal/bootstrap/certificate_*` | `tests/smoke/run.sh`, `internal/bootstrap/certificate_store_test.go` |
| FR-002 (certificate revoke path) | `/api/v1/certificates/{fingerprint}/revoke` | `API_V1_CERTIFICATES_REVOKE_CONTRACT.md` | `internal/bootstrap/handlers_certificates.go`, `internal/bootstrap/certificate_*` | `tests/smoke/run.sh`, `internal/bootstrap/certificate_store_test.go` |
| FR-002 (certificate renew path) | `/api/v1/certificates/{fingerprint}/renew` | `API_V1_CERTIFICATES_RENEW_CONTRACT.md` | `internal/bootstrap/handlers_certificates.go`, `internal/bootstrap/certificate_*` | `tests/smoke/run.sh`, `internal/bootstrap/certificate_store_test.go` |
| FR-002 (certificate download path) | `/api/v1/certificates/{fingerprint}/download` | `API_V1_CERTIFICATES_DOWNLOAD_CONTRACT.md` | `internal/bootstrap/handlers_certificates.go`, `internal/bootstrap/certificate_*` | `tests/smoke/run.sh`, `internal/bootstrap/certificate_store_test.go` |
| FR-002 (certificate import path) | `/api/v1/certificates/import` | `API_V1_CERTIFICATES_IMPORT_CONTRACT.md` | `internal/bootstrap/handlers_certificates.go`, `internal/bootstrap/certificate_*` | `tests/smoke/run.sh`, `internal/bootstrap/certificate_store_test.go` |

---

## NFR Evidence Summary

| NFR Class | Enforcement Path | Evidence |
|---|---|---|
| Security (fail-closed auth) | Unknown `AUTH_MODE` denied; invalid/missing token denied | `internal/bootstrap/auth.go`, smoke `401` checks |
| Security (auth path control) | API-key bearer auth path requires explicit enable flag | `internal/bootstrap/auth.go`, `internal/bootstrap/auth_config.go`, smoke api-key checks |
| Security (auth abuse controls) | Login/refresh per-client rate limiting | `internal/bootstrap/handlers_auth.go`, `internal/bootstrap/auth_rate_limit.go`, smoke auth endpoint checks |
| Security (fail-closed provider) | DB provider open/query errors return `503` | `handlers_protected_certs_summary.go`, smoke + unit tests |
| Contract stability | Canonical `405` behavior and unchanged `401` envelope | Phase 4 contract docs + smoke checks |
| Reliability | Graceful startup/shutdown and handler dependency checks | `internal/bootstrap/server.go`, `internal/bootstrap/handlers.go` |
| Operability (request correlation) | Request-id middleware with header echo/generation and context propagation | `internal/bootstrap/middleware_request_id.go`, `internal/bootstrap/middleware_request_id_test.go` |
| Operability | Test harness entrypoint used by CI | `scripts/test/run.sh`, `.github/workflows/ci-pr.yml`, `.github/workflows/ci-main.yml` |
| Operability (container profile) | Local hardened compose runtime profile | `docker-compose.yml`, `Dockerfile`, smoke harness |
| Architecture (provider DI) | All handler domains use injected provider interfaces with nil-check guards | `internal/bootstrap/handlers.go`, `internal/bootstrap/server.go`, unit tests |
| Architecture (fail-closed providers) | Protocol/discovery/notification/dashboard providers return `503` on errors | handler files + `provider_ws05_08_test.go` |
| Persistence (discovery DB) | DiscoveryProvider DB mode reads/writes W3 schema with parameterized queries | `discovery_db_provider.go`, `discovery_db_provider_test.go` |
| Persistence (notification DB) | NotificationProvider DB mode reads/writes W8 schema with parameterized queries | `notification_db_provider.go`, `notification_db_provider_test.go` |
| Persistence (dashboard action DB) | DashboardActionProvider DB mode reads/writes audit_log with parameterized queries | `dashboard_action_db_provider.go`, `dashboard_action_db_provider_test.go` |

---

## DB Discovery Adapter Coverage

| Mode | Selector | Expected Operations | Expected Failure Behavior | Evidence |
|---|---|---|---|---|
| File default | unset / `file` | Seed data + env-driven summaries | N/A | unit + smoke |
| DB + SQLite | `APP_DISCOVERY_PROVIDER=db`, `KRYPTKEEPER_DB_MODE=sqlite` | Real DB queries on W3 schema | `503` on open/query errors | unit tests |
| DB + Postgres | `APP_DISCOVERY_PROVIDER=db`, `KRYPTKEEPER_DB_MODE=postgres` | Real DB queries on W3 schema | `503` on missing DSN/open/query errors | unit tests |

## DB Notification Adapter Coverage

| Mode | Selector | Expected Operations | Expected Failure Behavior | Evidence |
|---|---|---|---|---|
| File default | unset / `file` | Seed data + env-driven summaries | N/A | unit + smoke |
| DB + SQLite | `APP_NOTIFICATION_PROVIDER=db`, `KRYPTKEEPER_DB_MODE=sqlite` | Real DB queries on W8 schema | `503` on open/query errors | unit tests |
| DB + Postgres | `APP_NOTIFICATION_PROVIDER=db`, `KRYPTKEEPER_DB_MODE=postgres` | Real DB queries on W8 schema | `503` on missing DSN/open/query errors | unit tests |

## DB Dashboard Action Adapter Coverage

| Mode | Selector | Expected Operations | Expected Failure Behavior | Evidence |
|---|---|---|---|---|
| File default | unset / `file` | Seed data history | N/A | unit + smoke |
| DB + SQLite | `APP_DASHBOARD_ACTION_PROVIDER=db`, `KRYPTKEEPER_DB_MODE=sqlite` | Audit_log aggregate queries | `503` on open/query errors | unit tests |
| DB + Postgres | `APP_DASHBOARD_ACTION_PROVIDER=db`, `KRYPTKEEPER_DB_MODE=postgres` | Audit_log aggregate queries | `503` on missing DSN/open/query errors | unit tests |

## DB Cert Summary Adapter Coverage

| Mode | Selector | Expected Source | Expected Failure Behavior | Evidence |
|---|---|---|---|---|
| File default | unset / `file` | `file-store` / `file-store-default` | N/A | unit + smoke |
| DB + SQLite | `APP_CERTS_SUMMARY_PROVIDER=db`, `KRYPTKEEPER_DB_MODE=sqlite` | `db-store-sqlite` | `503` on open/query errors | unit + smoke |
| DB + Postgres | `APP_CERTS_SUMMARY_PROVIDER=db`, `KRYPTKEEPER_DB_MODE=postgres` | `db-store-postgres` | `503` on missing DSN/open/query errors | unit + smoke (missing DSN fail-closed) |

---

## PR Gate Checklist (Phase 4)

- [ ] Requirement row(s) added/updated in this tracker
- [ ] Contract doc updated when shape/status semantics change
- [ ] At least one verification path updated (unit/integration/smoke)
- [ ] `go test ./...` passes
- [ ] `bash scripts/test/run.sh --suite protocol --suite integration --suite smoke` passes
