# Improvement Plan V2 — Crypto Core & Security

**Status:** Draft
**Created:** 2026-04-16
**Relationship to other plans:** Complements (does not replace) `docs/FULL_IMPROVEMENT_PLAN.md`, which covers bootstrap refactor and UX workflows. This plan focuses on the **crypto-core persistence, security fail-fasts, and protocol-completion gaps** that the earlier plan did not address. When an item appears in both plans, this one takes precedence for crypto/security concerns.

## Executive diagnosis

The backend is far more complete than a first-pass review suggests: 13 of 18 internal packages are real implementations (software keystore with Argon2id+AES-GCM, discovery scanner, CRL generator, OCSP responder framework, LDAP AD sync, notification delivery with retries). The DB schema already defines `certificate_authorities`, `certificates` (with `revoked_at`, `revocation_reason`), and `certificate_templates` tables.

**The core defect is wiring, not missing code.** The CA engine holds state in `map[string]*CA` and never touches the DB schema that already exists for it. OCSP and CRL handlers are production-grade but are instantiated in `cmd/kryptkeeper/main.go` with callback lambdas that return `false` / `nil` — so they sign "good" for every serial and publish empty CRLs. The ACME server has the same shape: real envelope code, no persistence, no challenge validation. The result is a platform that looks operational in the UI but cannot be trusted to actually enforce revocation, survive a restart, or replace ADCS.

Separately, the UI is a status console — operators cannot create a CA, issue a certificate, manage templates, sign in, or paginate past record 50. These flows don't exist even though the backend handlers for most of them do.

## Wave 0 — Security fail-fasts (1–3 days)

Self-contained code changes. No new subsystems. Goal: remove the ways the product can silently do the wrong thing before persistence lands.

| # | File / location | Change | Acceptance |
|---|---|---|---|
| 0.1 | `cmd/kryptkeeper/main.go:43–49` | Remove `APP_BOOTSTRAP_TOKEN` fallback for `KRYPTKEEPER_KEYSTORE_PASSPHRASE`. Require the dedicated env var. | Startup in CA mode with only `APP_BOOTSTRAP_TOKEN` set fails with a clear error. |
| 0.2 | `cmd/kryptkeeper/main.go:62–79` | Replace auto-create-root-CA-if-none-exist with **fail-fast**. A fresh process without a configured CA must refuse to start unless `KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true` is set explicitly. Emit a single-use bootstrap log line when it does create one. | Cold boot without the flag exits non-zero with "no CA configured — set KRYPTKEEPER_DEFAULT_CA_ID or re-run with KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true". |
| 0.3 | `cmd/kryptkeeper/main.go:188–191` | Remove default SCEP challenge `"kryptkeeper-scep"`. Require `KRYPTKEEPER_SCEP_CHALLENGE` when SCEP is enabled. | SCEP handler is only registered if a challenge is configured; absence logs a warning. |
| 0.4 | `internal/ca/engine.go:187–223` (`ImportCA`) | Reject imports where the cert is not self-signed but no issuer chain is provided. Add `ImportCAChain(name, chainPEM)` that verifies signatures before labeling root/intermediate. | New unit test asserts that a naked intermediate import is rejected. |
| 0.5 | `internal/ca/engine.go:225` (`IssueCertificate`) | Honor `req.IPAddresses` (currently only CSR SANs flow through). | Test issues a cert with request-level IPs and asserts they appear on the resulting leaf. |
| 0.6 | UI — `ui/src/components/ops-ui.tsx` or equivalent | Add a second-confirm ("type the CA name") gate for CA suspend and for certificate revoke. | Manual: clicking Suspend opens dialog requiring typed CA name before enabling the confirm button. |

## Wave 1 — PKI core persistence (5–10 days)

Goal: the CA engine, revocation list, and OCSP responder survive a restart and tell the truth.

| # | File / location | Change | Acceptance |
|---|---|---|---|
| 1.1 | `internal/ca/` — new `store.go` | Define `Store` interface: `Save(*CA)`, `Load(id)`, `List()`, `UpdateStatus(id, status)`. | Interface compiles; existing engine builds against it. |
| 1.2 | `internal/ca/store_postgres.go` (new) + `store_sqlite.go` (new) | Implement `Store` backed by the existing `certificate_authorities` table (schema already in `db/migrations/postgres/000002_templates_ca_certs_core.up.sql:35`). Persist key material by reference (the `KeyID` in the software keystore already survives; only metadata needs DB storage). | Integration test: create root CA → restart process → `ListCAs()` returns it; issued certs chain to the same SKI. |
| 1.3 | `internal/ca/engine.go:22` | Replace `cas map[string]*CA` with `store Store`; treat the map as a read-through cache. | Existing `engine_test.go` still passes against an in-memory store impl; new integration test passes against Postgres. |
| 1.4 | `internal/ca/revocation.go` (new) | `RevocationStore` interface: `Revoke(serial, caID, reason, when)`, `IsRevoked(serial, caID)`, `ListRevoked(caID)`. Backed by `certificates.revoked_at`, `certificates.revocation_reason` columns (see migration 000002 lines 97–98 and index `idx_cert_revoked_at` in 000005). | Unit test: revoke a cert, then `IsRevoked` returns true with the right reason and timestamp. |
| 1.5 | `cmd/kryptkeeper/main.go:151–155` | Replace the hardcoded `return false, ...` lambda with a call into `RevocationStore.IsRevoked`. | OCSP integration test: revoke a cert, issue an OCSP request, assert `revoked` status with the correct reason. |
| 1.6 | `cmd/kryptkeeper/main.go:170–173` | Replace `return nil, nil` lambda with `RevocationStore.ListRevoked(caID)`. | CRL test: revoke 3 certs, fetch CRL, assert all 3 serials present and CRL signed by correct CA. |
| 1.7 | `internal/bootstrap/handlers_certificates.go` — revoke handler | Call through to `RevocationStore.Revoke` after writing the cert update. | End-to-end test: POST `/certificates/:fp/revoke`, then OCSP for that serial returns revoked. |
| 1.8 | `internal/bootstrap/certificate_ca_provider.go` | On issue, persist leaf to `certificates` table (fingerprint, serial, ca_id, valid_until, etc.). | Newly issued certs appear in the list endpoint without a restart. |

## Wave 2 — Complete partial protocols (7–14 days)

Close the "wired but doesn't actually work" gaps flagged as PARTIAL / STUB.

| # | File / location | Change | Acceptance |
|---|---|---|---|
| 2.1 | `internal/acme/server.go:18–28` | Move `accounts`, `orders`, `authzs`, `certs` maps behind a `Store` interface; add Postgres/SQLite impls. | ACME client can complete a partial order across a process restart. |
| 2.2 | `internal/acme/server.go` (challenges) | Implement HTTP-01 validation: fetch `http://<identifier>/.well-known/acme-challenge/<token>` with a short-timeout client and compare to `KeyAuthorization`. | `certbot` dry-run against the local server issues a cert for a reachable test domain. |
| 2.3 | `internal/acme/server.go` (challenges) | Implement TLS-ALPN-01 or DNS-01 (pick one). | Challenge end-to-end test with the chosen type. |
| 2.4 | `internal/xcep/server.go` | Complete GetPolicies SOAP response marshaling per MS-XCEP §3.1.4.1. Add response envelope with `xcep:GetPoliciesResponse`. | Test with a captured Windows client request returns a well-formed response; template OIDs and version numbers present. |
| 2.5 | `internal/cmp/server.go` | Complete PKIMessage → IssueCertificate → PKIResponse path for `ir` (initial request) and `cr` (cert request) types. | Integration test using `openssl cmp` issues a cert against the local CMP endpoint. |
| 2.6 | `internal/keystore/cloudkms.go:49–62` | Implement the AWS KMS provider (highest customer demand; defer GCP and Azure). Uses `aws-sdk-go-v2/service/kms`. `crypto.Signer.Sign` calls `kms.Sign` with the configured key ID. | Issuing with a KMS-backed CA works end-to-end against LocalStack KMS. |
| 2.7 | `internal/bootstrap/certificate_ca_provider.go` — template enforcement | Plumb `IssuanceRequest.TemplateID` through to template validation (algo constraints, validity max, EKU allow-list). Reject violations with `ErrPolicyViolation` from `internal/ca/ca.go:16`. | Request with a disallowed EKU against a restrictive template returns 422 with policy-violation message. |

## Wave 3 — UI creation & issuance flows (7–14 days)

The UI currently can't start a PKI. Add the flows that turn it into an operable product.

| # | File / location | Change | Acceptance |
|---|---|---|---|
| 3.1 | `ui/src/pages/CAs.tsx` | Add "Create CA" primary action. New dialog with type (root/intermediate), subject DN fields, algorithm (ECDSA P-256 / P-384 / RSA 3072), validity, parent CA (if intermediate). Wire to `POST /api/v1/cas` (add handler if missing in `internal/bootstrap/handlers_cas.go`). | Manual: new operator can create a root CA from the UI without env-var gymnastics. |
| 3.2 | `ui/src/pages/Certificates.tsx:33` | Add "Issue certificate" flow: template select, subject DN, SANs, CSR paste or generate-in-browser (Web Crypto API, with private key stored locally and exported). Move Import out of the detail panel into a top-level action. | Issue → cert appears in inventory, chains correctly, OCSP returns good. |
| 3.3 | `ui/src/pages/Templates.tsx` (new) + route in `App.tsx` | Template CRUD UI — list, detail, create, edit, delete. Call `/api/v1/templates` (handlers already exist per `handlers_templates.go`). | Create a template in UI, then issue against it and see the constraints applied. |
| 3.4 | `ui/src/pages/Login.tsx` (new) + route | Login flow using `POST /api/v1/auth/login`; token stored per existing `auth.tsx` pattern; unauthenticated users redirect to `/login`. | Fresh browser → redirected to login; after auth, role badge shows real role. |
| 3.5 | All list pages | Add pagination (cursor or offset; backend should already support `limit` + needs `cursor`/`offset`). Replace hardcoded `limit: 50` in `Certificates.tsx:60` / Discovery / Alerts with server-driven pagination. | Scroll past 50 records works; back/forward preserves page. |
| 3.6 | `ui/src/pages/Search.tsx:22–26` | Remove client-side filtering over 5 truncated queries. Route to a single `GET /api/v1/search?q=...` endpoint (new — delegates to per-domain search in handlers). | Search for a fingerprint that's on record 1,000 finds it. |
| 3.7 | `ui/src/pages/Discovery.tsx:176` | Wire "Inspect certificate" onClick to navigate to the matched certificate detail. | Clicking from a discovery endpoint jumps to the associated cert record. |
| 3.8 | `ui/src/lib/api.ts` | Call or remove unused endpoints (`api.meta`, `api.ca`, `api.certificate`, `api.certificateChain`, `api.protocolsStatus`). If used later, leave a TODO with owner. | No dead exports in `api.ts`. |

## Wave 4 — UX polish (5–7 days)

All the friction items that don't require new subsystems.

| # | File / location | Change | Acceptance |
|---|---|---|---|
| 4.1 | `ui/src/pages/Certificates.tsx:196–211` | Replace free-text Inputs for `status`, `grade`, `team_id`, `ca_id` with Selects. Populate `status`/`grade` from enum; `team_id`/`ca_id` from lookup queries. | No more guessing valid values. |
| 4.2 | `ui/src/pages/CAs.tsx:145`, `Alerts.tsx`, `Discovery.tsx` | Same treatment — wherever a server enum exists, use a Select. | UI filter consistency audit passes. |
| 4.3 | Certificate detail panel (`Certificates.tsx:304`) | Expand to show SANs, EKU, key algo, serial, SKI, chain-to-root visualization, PEM copy, revocation history. | Detail panel is usable for incident response. |
| 4.4 | All mutation error handlers | Surface server error message (not just "Try again in a moment"). Normalize error shape in `api.ts` so every handler can show `error.message`. | Revoke with invalid reason code shows the real validation error. |
| 4.5 | All filter states | Persist filter state in URL search params so refresh and share-link work. | `/certificates?status=expired&grade=C` loads filtered view directly. |
| 4.6 | `Alerts.tsx:18` | Remove hardcoded `ops@example.com` default target. Empty by default; inline help suggests format per selected channel. | No accidental sends to fake address. |
| 4.7 | Dashboard `Next best actions` (`Dashboard.tsx:31–50`) | Suppress actions with zero signal. When all green, show a success state instead of three low-urgency cards. | Zero-state dashboard is calm, not falsely alarming. |
| 4.8 | `Discovery.tsx:241` | Replace `JSON.stringify(job.scope)` with a typed scope renderer. | Scope cell is human-readable. |

## Wave 5 — Hardening (ongoing, 5–7 days to land baseline)

| # | Area | Change | Acceptance |
|---|---|---|---|
| 5.1 | A11y | Add `scope="col"` to all `<th>`; fix `main#main-content` `tabIndex={-1}` in `App.tsx:63` so skip link lands correctly. Run axe against every page. | Zero critical axe violations. |
| 5.2 | CSRF | Add CSRF token on state-changing requests OR document that Bearer auth + same-origin is the enforced posture. | Security doc explicit; tests cover chosen posture. |
| 5.3 | Observability | Add metrics + structured log fields for: OCSP hit/miss, revoked lookups, issue latency, CA signing duration, scan job queue depth. | `/metrics` endpoint exposes the counters; a starter Grafana dashboard JSON is checked in. |
| 5.4 | Rate limits | Add per-IP rate limits on ACME, SCEP, EST, OCSP, and the auth endpoint. Reuse existing `auth_rate_limit.go` pattern. | Flood test returns 429 after threshold. |
| 5.5 | Tests | Backfill integration tests for: full issue → revoke → OCSP revoked → CRL contains serial path; ACME end-to-end; fresh-process CA persistence; template policy rejection. | `go test ./...` includes these and passes. |
| 5.6 | Docs | Update `DOCS_INDEX.md` to reference this plan. Update `docs/HEALTH_ASSESSMENT.md` scores after each wave. Move this file to `docs/reviews/` when complete. | Index accurately reflects current state. |

## Dependencies and ordering

```
Wave 0 ──┬──► Wave 1 ──┬──► Wave 2 ──► Wave 3 ──► Wave 5
         │             │
         └──► Wave 3.1─4 (CA create UI) can start in parallel once 1.2 lands
                       │
                       └──► Wave 4 can start after any of 3.1 / 3.2 / 3.5 ships
```

- Wave 0 gates everything — ship first.
- Wave 1 gates Waves 2 and 5 (testing revocation paths).
- Wave 3's backend-needed pieces (3.1, 3.2, 3.3, 3.6) depend on Wave 1's DB wiring.

## Rough effort

| Wave | Calendar time (1 engineer) |
|------|---|
| 0 | 1–3 days |
| 1 | 5–10 days |
| 2 | 7–14 days |
| 3 | 7–14 days |
| 4 | 5–7 days |
| 5 | 5–7 days to baseline, then ongoing |
| **Total to V1-worthy** | **~30–55 days single-threaded** |

Waves 3 and 4 parallelize across one backend and one frontend engineer.

## Out of scope (track for V2/V3)

- Full Cloud KMS coverage (GCP, Azure)
- Windows auto-enrollment end-to-end (XCEP is in Wave 2; domain-joined client flow is V2)
- Kubernetes operator / Terraform provider (Research doc mentions these)
- PQC wet signatures (planner is real; actually issuing ML-DSA is V3)
- Multi-tenant isolation

## Open questions

1. Does the team have a prod Postgres to point CI integration tests at, or should Wave 1 ship with Testcontainers?
2. Should CA creation require a second operator approval (two-person rule), or is single-operator sufficient for V1?
3. Cloud KMS provider priority — confirm AWS > GCP > Azure is right for target customers.
4. Should the CA hierarchy support offline root (key exported, online intermediate signs) in V1, or defer?

## How to resume

Start a new session with:
> "Resume Kryptkeeper improvement plan. Read `docs/IMPROVEMENT_PLAN_V2.md` and memory `memory/kryptkeeper-improvement-plan.md`. Begin Wave 0, task 0.1."
