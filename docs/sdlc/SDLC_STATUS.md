# Kryptkeeper — SDLC Status

> **HISTORICAL (frozen 2026-07-15, design review G-7 / DECISIONS.md D-018):** the V1–V4 cycle scheme below is frozen; "V4 IN PLANNING" predates shipped v1.5–v2.2. Current truth: `docs/SESSION_STATUS.md`, `docs/DECISIONS.md`, `CHANGELOG.md`.

**Project:** Kryptkeeper
**Mode:** init (new project)
**Started:** 2026-04-05

---

## Phase Completion

| Phase | Name | Status | Deliverables |
|-------|------|--------|-------------|
| 0 | Ideation | COMPLETE | VISION.md |
| 1 | Planning | COMPLETE | SCOPE.md, RISKS.md, CONSTRAINTS.md, USER_PERSONAS.md |
| 2 | Requirements | COMPLETE | SRS.md, USER_STORIES.md |
| 3 | Design | COMPLETE | ARCHITECTURE.md ✓, TECH_STACK.md ✓, DATABASE.md ✓, THREAT_MODEL.md ✓, API_DESIGN.md ✓ |
| 4 | Implementation (API + Persistence) | COMPLETE | 10/10 workstreams DONE, 8 migration waves, 11 providers, 2 security audit rounds |
| 4b | Implementation (Crypto + Protocols + UI) | COMPLETE | 13/13 workstreams DONE: crypto engine, 5 protocol servers, scanner, alerts, dashboard, compose, OpenAPI |
| 5 | Review | COMPLETE | Phase 4a approved 2026-04-08; Phase 4b approved 2026-04-08; V1 MVP implementation complete |
| V2 | ADCS Replacement | COMPLETE (code) | 7/8 workstreams DONE; WS-08 (Windows E2E) requires AD DS test environment — deferred to integration testing |
| V3 | Full Crypto Management | COMPLETE (code) | 6/6 workstreams: SSH key inventory, code-signing tracking, cipher audit, PQC migration planner, CMP server |
| V4 | PQC + Key Mgmt + Go to Market | **IN PLANNING** | VISION_V4.md ✓, SCOPE.md ✓, RISKS.md ✓, IMPLEMENTATION_PLAN.md ✓, GTM.md ✓ |

---

## Gate Status

| Gate | Status | Notes |
|------|--------|-------|
| Phase 0 → 1 | APPROVED | Research pre-completed; decisions carried forward |
| Phase 1 → 2 | APPROVED | All 4 planning docs complete |
| Phase 2 → 3 | APPROVED | SRS.md and USER_STORIES.md complete with acceptance criteria and metrics |
| Phase 3 → 4 | APPROVED | All design docs complete; architecture updated with explicit end-to-end data flow diagram |
| Phase 4 → 5 | APPROVED | 10/10 workstreams DONE; 61 contract docs; W1-W8 migrations; 9 providers + 5 DB adapters; 2 security audit rounds (0 CRITICAL/HIGH); build+test+smoke green |
| Phase 4b → 5 | APPROVED | 13/13 workstreams DONE; crypto engine + 5 protocol servers + scanner + alerts + dashboard + compose + OpenAPI; 11 Go packages, 60+ tests, React build clean |

### Phase 4 → 5 Confidence Gate Check

| Deliverable | Completeness | Quality | Pass? |
|-------------|--------------|---------|-------|
| Contract documents (61 endpoint contracts) | 9 | 9 | YES |
| Workstream completion (10/10 DONE) | 10 | 9 | YES |
| Migration coverage (W1-W8, SQLite + Postgres) | 9 | 8 | YES |
| Provider interfaces + DI wiring (9 interfaces, 11 injected) | 9 | 9 | YES |
| DB adapter coverage (5 adapters, SQLite + Postgres) | 9 | 8 | YES |
| File adapter coverage (9 adapters) | 9 | 8 | YES |
| Security audit closure (6 reports, 0 CRITICAL/HIGH remaining) | 9 | 9 | YES |
| Input validation hardening (allowlists, length caps, LIKE escaping) | 9 | 9 | YES |
| Unit test coverage (13 test files) | 8 | 8 | YES |
| Smoke harness coverage (bootstrap + jwt mode) | 9 | 8 | YES |
| FR/NFR traceability tracker | 9 | 8 | YES |
| CI/CD pipeline baseline (6 workflows) | 9 | 8 | YES |
| Container baseline (Dockerfile + compose) | 9 | 8 | YES |

**Overall confidence:** 8 (min score)
**Gate status:** PASS (all deliverables >= 7)

**Scope note:** Phase 4 delivered the V1 API contract + persistence foundation. The crypto engine, protocol servers (ACME/EST/SCEP/OCSP), real discovery scanner, and dashboard UI are scoped for the next implementation cycle (Phase 4b).

### Phase 3 → 4 Confidence Gate Check

| Deliverable | Completeness | Quality | Pass? |
|-------------|--------------|---------|-------|
| ARCHITECTURE.md | 9 | 8 | YES |
| TECH_STACK.md | 9 | 8 | YES |
| DATABASE.md | 9 | 8 | YES |
| THREAT_MODEL.md | 9 | 8 | YES |
| API_DESIGN.md | 9 | 8 | YES |

**Overall confidence:** 8 (min score)  
**Gate status:** PASS (all deliverables >= 7)

---

## Key Decisions (Locked)

| Decision | Rationale | ADR |
|----------|-----------|-----|
| Go for all backend services | step-ca/Boulder/cfssl precedent; stdlib crypto; single binary | From research |
| TypeScript/React + shadcn/ui for dashboard | Right tool for UI; separate from CA core | From research |
| PostgreSQL primary + SQLite dev | HA, analytics, SQLite for embedded | From research |
| Apache 2.0 license | Patent grant; enterprise legal requirement; no copyleft | From research |
| crypto.Signer interface for all signing | HSM/KMS/software swappability without CA logic changes | From research |
| OCSP free in OSS | Explicit competitive differentiator vs step-ca | From research |
| XCEP/WSTEP path for ADCS (not DCOM) | DCOM requires Windows CA; XCEP/WSTEP is HTTP/SOAP | From research |
| Two-phase discovery (masscan + Go TLS) | masscan TLS extraction is limited; separation of concerns | From research |

---

## Next Actions

1. Resolve blocking contract decisions before broad implementation:
   - Complete: `phase-4-implementation/BLOCKING_DECISIONS.md` approved
2. Convert migration waves to concrete migration file manifest and sequencing
   - Complete: `phase-4-implementation/MIGRATION_MANIFEST.md`
   - Scaffolding complete: migration skeleton files created in `internal/db/migrations/{postgres,sqlite}/`
   - Wave W1 implemented (foundations + identity) for both PostgreSQL and SQLite
   - Wave W2 implemented (templates/CA/certificates core) for both PostgreSQL and SQLite
   - Wave W3 implemented (discovery/endpoints core) for both PostgreSQL and SQLite
   - Wave W4 implemented (audit append-only controls) for both PostgreSQL and SQLite
   - Wave W5 implemented (P0 query indexes) for both PostgreSQL and SQLite
   - Wave W6 implemented (engine-specific perf features) for both PostgreSQL and SQLite
   - Wave W7 implemented (deterministic CI seed data) for both PostgreSQL and SQLite
   - SQLite full chain W1→W7 up/down validated
3. Stand up CI workflow skeletons (`.github/workflows`) for PR/main/release gates
   - Design complete: `phase-4-implementation/CICD_WORKFLOW_MANIFEST.md`
   - Scaffolding complete: 6 workflow YAML files created under `.github/workflows/`
   - `ci-pr.yml` upgraded to executable baseline checks
   - `ci-main.yml` upgraded to executable baseline checks
   - `release-candidate.yml`, `promote-by-digest.yml`, and `rollback-by-digest.yml` upgraded to executable baselines
   - `nightly-scale-and-protocol.yml` upgraded to executable baseline
   - Deployment helpers added: `scripts/deploy/by-digest.sh` and `scripts/deploy/smoke.sh`
   - Promotion/rollback workflows now consume env-specific deploy and smoke configuration via secrets
    - Release workflow now executes buildx multi-arch build, digest capture, SBOM generation, and cosign signing
    - Promotion/rollback now verify digest existence + signature prior to deployment
    - Root `Dockerfile` and `.dockerignore` added to support release image build
    - Dockerfile upgraded to dual-mode build (`BUILD_MODE=placeholder|real`) with non-root distroless runtime
    - Go bootstrap app entrypoint added (`go.mod`, `cmd/kryptkeeper/main.go`) for `BUILD_MODE=real`
    - P0 test harness runner added (`scripts/test/run.sh`) with concrete protocol/integration checks under `tests/`
    - Runtime smoke checks now validate `/`, `/healthz`, `/readyz`, and `/api/v1/meta` bootstrap behavior
    - First auth-protected bootstrap endpoint added: `/api/v1/authz-check` + contract/tests
    - JWT transition mode added for `/api/v1/authz-check` (`AUTH_MODE=jwt`, HS256 claims validation)
    - OIDC/JWKS transition mode added for `/api/v1/authz-check` (`AUTH_MODE=oidc`, RS256/JWKS validation)
    - CI runtime smoke now enforces auth-mode matrix (bootstrap + jwt + oidc)
    - Managed OIDC discovery/JWKS refresh path added for `AUTH_MODE=oidc`
    - OIDC discovery/JWKS rotation operational runbook added (`docs/ops/OIDC_JWKS_RUNBOOK.md`)
    - First protected resource endpoint added: `GET /api/v1/protected/ping` + contract/tests
    - Second protected resource endpoint added: `GET /api/v1/protected/whoami` + contract/tests
    - Third protected resource endpoint added: `GET /api/v1/protected/config` + contract/tests
    - Fourth protected resource endpoint added: `GET /api/v1/protected/certs/summary` + contract/tests
    - Runtime smoke CI gate stabilized to single harness entrypoint (check context unchanged)
    - Persistence provider abstraction introduced for cert summary (`CertSummaryProvider` + file adapter)
    - Auth/handler wiring split into feature-sliced internal modules (`auth_*`, `handlers_*`, `response.go`)
    - Cert summary provider selector added with explicit `APP_CERTS_SUMMARY_PROVIDER=db` path (default remains file-backed)
    - DB-backed cert summary now supports both SQLite and Postgres adapter selection via `KRYPTKEEPER_DB_MODE`
    - Runtime smoke now validates sqlite DB-backed cert summary response and postgres-mode missing-DSN fail-closed behavior
    - Initial audit query contract and endpoint added: `GET /api/v1/audit` with file/db providers and fail-closed `503`
    - Audit append write path instrumentation now logs auth/protected/audit read outcomes (success/denied/failure) through provider adapters
    - Audit list endpoint now supports initial filter and cursor pagination query parameters (`action`, `actor_type`, `resource_type`, `limit`, `cursor`, `order`)
    - Audit list endpoint filter set expanded with actor/resource/trace/time query semantics (`actor_id`, `resource_id`, `trace_id`, `after`, `before`)
    - WS-04 kickoff: initial Core PKI list endpoint added (`GET /api/v1/cas`) with file-backed provider, auth baseline, and filter/pagination metadata
    - WS-04 CA detail read endpoint added (`GET /api/v1/cas/{id}`) with not-found and fail-closed behaviors
    - WS-04 CA chain read endpoint added (`GET /api/v1/cas/{id}/chain`) with `json` default and `pem` format mode
    - WS-04 CA state transitions added (`POST /api/v1/cas/{id}/suspend`, `POST /api/v1/cas/{id}/activate`) with conflict and not-found handling
    - WS-04 CA mutable update endpoint added (`PATCH /api/v1/cas/{id}`) with immutable-field and invalid-field validation
    - WS-04 CA delete endpoint added (`DELETE /api/v1/cas/{id}`) with state precondition and active-certificate conflict checks
    - WS-04 template read baseline endpoints added (`GET /api/v1/templates`, `GET /api/v1/templates/{id}`)
    - Provider injection is now explicit at handler registration time (no implicit nil fallback)
    - Provider-specific cert summary logs are internal-only and do not affect the public v1 contract
    - `discovery_enabled` now reflects active managed OIDC discovery only
    - Server lifecycle moved into `internal/bootstrap/server.go`; `main.go` is composition-only
    - Handler registration now validates auth/provider injection upfront
    - Unknown `AUTH_MODE` now fails closed (security hardening)
    - Phase-4 API/auth contracts normalized to canonical 405 baseline
    - Branch protection required check names finalized in `docs/ops/workflow-hardening-report-2026-04-06.md`
4. Execute implementation with Workstream WS-01 (contract foundation), WS-02 (identity/access), WS-09 (container), and WS-10 (CI/CD) now IN PROGRESS
5. Implement P0 test cases from `docs/TEST_STRATEGY.md` in parallel with WS-01/WS-02

**Current focus (V4):** Sprint 3 implementation — WS-01 (ML-DSA keystore spike) is the immediate unblock. Start with the Go x509 compatibility spike before committing to the full ML-DSA workstream. See `docs/sdlc/v4-planning/IMPLEMENTATION_PLAN.md`.

**V4 document index:**
```
docs/sdlc/v4-planning/
  SCOPE.md              ← Sprint 3 + Sprint 4 + OSS Launch scope, done criteria
  RISKS.md              ← 11 risks with likelihood/impact/mitigations
  IMPLEMENTATION_PLAN.md ← 10 workstreams, dependency graph, 14-week timeline
  GTM.md                ← Positioning, pricing, launch sequence, success metrics
docs/sdlc/phase-0-ideation/
  VISION_V4.md          ← Updated vision: Crypto Trust Platform, key management, PQC, Microsoft
docs/SPRINT_3_PLAN.md   ← Narrative plan (created 2026-04-24)
```

---

## Document Index

```
docs/sdlc/
  SDLC_STATUS.md                    ← this file
  phase-0-ideation/
    VISION.md                       ← product vision, problem, personas, success metrics
  phase-1-planning/
    SCOPE.md                        ← V1/V2/V3 boundaries, service inventory, done criteria
    RISKS.md                        ← 14 risks with likelihood/impact/mitigation
    CONSTRAINTS.md                  ← 18 constraints across team/tech/time/security/ops
    USER_PERSONAS.md                ← 5 personas with goals, pain points, evaluation criteria
  phase-2-requirements/
    SRS.md                          ← IEEE 830 SRS: 56 FRs (V1) + V2/V3, 31 NFRs, traceability matrix
    USER_STORIES.md                 ← 43 stories across 7 epics, 252 story points
  phase-3-design/
    ARCHITECTURE.md                 ← C4 diagrams, plugin registry, module structure, ADRs, data flows
    TECH_STACK.md                   ← All technology decisions with versions and rationale
    DATABASE.md                     ← Full schema (13 tables), ERD, indexes, migrations, SQLite compat
    THREAT_MODEL.md                 ← STRIDE analysis, trust boundaries, 24 threats, 30 controls
    API_DESIGN.md                   ← OpenAPI-style contract with auth, pagination, error catalog
  phase-4-implementation/
    IMPLEMENTATION_PLAN.md          ← Workstream order, blockers, gate policy
    WORKSTREAM_TRACKER.md           ← Execution tracker with dependencies and risks
    BLOCKING_DECISIONS.md           ← Proposed DEC-001..DEC-005 approval record
    MIGRATION_MANIFEST.md           ← Exact W1..W7 migration filenames and rollback/CI order
    CICD_WORKFLOW_MANIFEST.md       ← Exact GitHub Actions workflow manifest and gate matrix
    BOOTSTRAP_CONTRACT_MATRIX.md    ← Executable contract matrix for bootstrap endpoints and smoke flow
    API_V1_MINIMAL_CONTRACT.md      ← Minimal `/api/v1/meta` contract + forward-compat rules
    AUTH_V1_MINIMAL_CONTRACT.md     ← Minimal auth-protected `/api/v1/authz-check` contract
    AUTH_JWT_TRANSITION_CONTRACT.md ← Transitional JWT auth contract for `/api/v1/authz-check`
    AUTH_OIDC_JWKS_CONTRACT.md      ← Transitional OIDC/JWKS auth contract for `/api/v1/authz-check`
    AUTH_OIDC_DISCOVERY_CONTRACT.md ← Managed OIDC discovery + JWKS refresh contract
    API_V1_PROTECTED_RESOURCE_CONTRACT.md ← First protected resource contract (`/api/v1/protected/ping`)
    API_V1_PROTECTED_WHOAMI_CONTRACT.md ← Second protected resource contract (`/api/v1/protected/whoami`)
    API_V1_PROTECTED_CONFIG_CONTRACT.md ← Third protected resource contract (`/api/v1/protected/config`)
    API_V1_PROTECTED_CERTS_SUMMARY_CONTRACT.md ← Fourth protected resource contract (`/api/v1/protected/certs/summary`)
  phase-5-review/                   ← (pending)
  v2-implementation/
    IMPLEMENTATION_PLAN.md          ← V2 workstreams, dependency graph, risks, delegation plan
  diagrams/                         ← (pending — C4 + sequence + ERD)

docs/research/
  RESEARCH_FINDINGS.md              ← Foundation document — do not modify

docs/
  TEST_STRATEGY.md                  ← Phase 4 test strategy from delegated test expert
  DATABASE.md                       ← Phase 4 migration and data-access implementation plan from delegated DBA
  ops/workflow-hardening-report-2026-04-06.md  ← SRE hardening report for workflow gates/secrets
  ops/OIDC_JWKS_RUNBOOK.md          ← OIDC discovery/JWKS rotation operations runbook
```
