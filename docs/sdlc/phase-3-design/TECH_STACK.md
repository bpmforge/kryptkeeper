# Kryptkeeper — Technology Stack

**Version:** 1.0
**Date:** 2026-04-05
**Phase:** 3 — Design

All technology choices in this document are final for V1 unless a specific version
note says otherwise. Decisions are grounded in RESEARCH_FINDINGS.md §3 and constrained
by CONSTRAINTS.md. Where a choice was contested, the rationale explains what was rejected
and why.

---

## Table of Contents

1. [Backend — Go](#1-backend--go)
2. [Frontend — React](#2-frontend--react)
3. [Database](#3-database)
4. [Infrastructure and Deployment](#4-infrastructure-and-deployment)
5. [Observability](#5-observability)
6. [Testing](#6-testing)
7. [Build and Toolchain](#7-build-and-toolchain)
8. [Security Tooling](#8-security-tooling)
9. [Version Compatibility Matrix](#9-version-compatibility-matrix)
10. [Dependency License Summary](#10-dependency-license-summary)

---

## 1. Backend — Go

### Language

| Decision | Value |
|----------|-------|
| **Language** | Go |
| **Minimum Version** | Go 1.24 |
| **Target Version** | Go 1.24 (current stable) |
| **Version rationale** | Go 1.24 ships `crypto/tls` with hybrid PQC (X25519MLKEM768) support for the CA API server at no cost. Go 1.21 introduced `log/slog` (used for structured logging). Go 1.22 fixed loop variable capture semantics. |

**Why Go over alternatives:** Documented in ADR-001 (ARCHITECTURE.md). In short: every
production open-source CA (step-ca, Boulder, cfssl) uses Go. The `crypto/x509` stdlib is
the right tool — no equivalent exists in Rust or Node.js for X.509 certificate lifecycle.
Single static binary deployment is non-negotiable for the agent constraint (C-Ops02).

### Standard Library — Cryptography (No Third-Party Replacement)

| Package | Purpose | Notes |
|---------|---------|-------|
| `crypto/x509` | X.509 certificate parsing, generation, chain validation | MUST be the only X.509 implementation (C-Tech02) |
| `crypto/tls` | TLS configuration for all HTTPS servers | Prefer TLS 1.3; set `MinVersion: tls.VersionTLS12` |
| `crypto/rand` | Cryptographically secure random number generation | MUST be used for all key generation and serial numbers |
| `crypto/rsa`, `crypto/ecdsa`, `crypto/ed25519` | Key type implementations | Called only through `crypto.Signer` |
| `crypto/elliptic` | P-384 curve operations | |
| `encoding/pem`, `encoding/asn1` | PEM/DER encoding and ASN.1 parsing | |

### Third-Party Cryptographic Libraries

| Library | Version | Purpose | License | Notes |
|---------|---------|---------|---------|-------|
| `golang.org/x/crypto` | Latest | Argon2id KDF, OCSP request/response encoding, additional cipher support | BSD-3 | Golang extended standard library, maintained by Go team |
| `github.com/cloudflare/circl` | v1.3.x+ | ML-DSA (FIPS 204 / Dilithium) for V2 PQC issuance | BSD-3 | Cloudflare's production PQC library. Switch to Go stdlib when ML-DSA lands (~Go 1.26) |
| `github.com/ThalesGroup/crypto11` | v1.2.x+ | PKCS#11 HSM integration — wraps C_Sign as `crypto.Signer` | MIT | The standard Go PKCS#11 binding. Required for HSM key storage (FR-004) |

**Note on PQC:** Go 1.24 added ML-KEM for TLS key exchange but not ML-DSA for certificate
signing. Cloudflare CIRCL fills this gap until Go 1.26. The `crypto.Signer` abstraction
means the transition to stdlib ML-DSA requires only a backend swap, no CA logic changes.

### HTTP Routing

| Library | Version | Purpose | License |
|---------|---------|---------|---------|
| `github.com/go-chi/chi/v5` | v5.x | HTTP router for REST API and protocol servers | MIT |

**Rationale for chi:** Lightweight, idiomatic Go, fully compatible with `net/http` middleware
ecosystem. No code generation, no reflection-heavy magic. Gin was considered but chi has a
smaller surface area and better alignment with stdlib patterns. Fiber was rejected (uses
fasthttp, not `net/http`, complicates middleware reuse).

### ACME Protocol

| Library | Version | Purpose | License |
|---------|---------|---------|---------|
| `github.com/mholt/acmez` | v2.x | ACME RFC 8555 client-side reference implementation | Apache 2.0 |

**Note:** Kryptkeeper implements an ACME *server*, not a client. `acmez` is used as a
reference implementation and potentially for the challenge-validation client code. The
ACME server endpoint itself is written from scratch following RFC 8555. Study Boulder
(Let's Encrypt) as the authoritative ACME server reference.

### Database Drivers

| Library | Version | Purpose | License |
|---------|---------|---------|---------|
| `github.com/jackc/pgx/v5` | v5.x | PostgreSQL driver — idiomatic Go, supports `pgx.Conn` and `database/sql` | MIT |
| `github.com/mattn/go-sqlite3` | v1.14.x | SQLite driver (cgo) for single-node mode | MIT |
| `github.com/golang-migrate/migrate/v4` | v4.x | Database schema migrations (SQL files, both PostgreSQL and SQLite) | MIT |

**Note on SQLite + cgo:** `mattn/go-sqlite3` requires CGO, which complicates cross-compilation.
The agent binary (`kk-agent`) does NOT use SQLite and is compiled with `CGO_ENABLED=0` for
pure-static binaries. The server binary accepts the CGO dependency.

### Configuration and CLI

| Library | Version | Purpose | License |
|---------|---------|---------|---------|
| `github.com/spf13/cobra` | v1.8.x | CLI command structure (`kk ca create`, `kk agent start`, etc.) | Apache 2.0 |
| `github.com/spf13/viper` | v1.18.x | Configuration file + environment variable binding | MIT |

**Configuration precedence (highest to lowest):** CLI flags → Environment variables →
Config file (YAML/TOML) → Defaults. Config file path: `$KRYPTKEEPER_CONFIG` or
`/etc/kryptkeeper/config.yaml`.

### Structured Logging

| Library | Version | Purpose | License |
|---------|---------|---------|---------|
| `log/slog` | Go stdlib | Structured logging (JSON in production, text in development) | Go stdlib |

`slog` was added in Go 1.21. No third-party logging library is needed. External
libraries that log must be wrapped to emit via `slog`.

### Metrics and Observability

| Library | Version | Purpose | License |
|---------|---------|---------|---------|
| `github.com/prometheus/client_golang` | v1.19.x | Prometheus metrics exposition | Apache 2.0 |
| `go.opentelemetry.io/otel` | v1.x | OpenTelemetry tracing (optional OTLP export) | Apache 2.0 |

### Additional Backend Libraries

| Library | Version | Purpose | License |
|---------|---------|---------|---------|
| `github.com/google/uuid` | v1.6.x | UUID generation for primary keys | BSD-3 |
| `github.com/golang-jwt/jwt/v5` | v5.x | JWT parsing and validation (OIDC tokens, dashboard sessions) | MIT |
| `golang.org/x/net` | Latest | HTTP/2 support, network utilities | BSD-3 |
| `github.com/robfig/cron/v3` | v3.x | Cron scheduling for scan jobs and expiry monitoring | MIT |

### Explicitly Rejected Backend Libraries

| Library | Why Rejected |
|---------|-------------|
| `github.com/gin-gonic/gin` | Uses reflection for parameter binding; chi is simpler and more idiomatic |
| `github.com/gofiber/fiber` | fasthttp breaks `net/http` middleware compatibility |
| `go.uber.org/zap` | Unnecessary now that `log/slog` is in stdlib with comparable performance |
| `gorm.io/gorm` | ORM abstraction leaks SQL details; raw SQL with pgx is more predictable for complex queries |
| `github.com/square/go-jose` | No longer maintained; `golang-jwt/jwt` covers requirements |

---

## 2. Frontend — React

### Language and Framework

| Decision | Value |
|----------|-------|
| **Language** | TypeScript 5.4+ |
| **Framework** | React 18+ |
| **Build tool** | Vite 5.x |
| **Package manager** | pnpm (lockfile committed; consistent installs) |

### Component Library

| Library | Version | Purpose | License |
|---------|---------|---------|---------|
| `shadcn/ui` | Latest (CLI-installed, not a package) | Accessible component primitives (copied into repo, not a runtime dep) | MIT |
| `@radix-ui/react-*` | Latest | Underlying Radix UI primitives used by shadcn | MIT |
| `tailwindcss` | v3.4.x | Utility-first CSS | MIT |
| `class-variance-authority` | Latest | Variant-based class management for shadcn components | MIT |
| `lucide-react` | Latest | Icon set used by shadcn | ISC |

**Why shadcn/ui:** Components are copied into the repository via the shadcn CLI, not
imported as a versioned npm package. This means: zero runtime dependency on shadcn, full
ability to customize components, and no upstream breaking changes. The accessibility
(WCAG 2.1 AA) baseline from Radix UI is included for free.

### State Management and Data Fetching

| Library | Version | Purpose | License |
|---------|---------|---------|---------|
| `@tanstack/react-query` | v5.x | Server state management, caching, background refetching | MIT |
| `@tanstack/react-router` | v1.x | Type-safe client-side routing | MIT |
| `zustand` | v4.x | Minimal client-side UI state (modals, notification toasts) | MIT |

**Why TanStack Query:** Certificate inventory, scan results, and risk dashboards involve
paginated, filtered server data that benefits from caching and background refetching.
TanStack Query handles this cleanly without Redux boilerplate. Zustand handles the small
amount of purely local UI state (no server state in Zustand).

### Data Visualization

| Library | Version | Purpose | License |
|---------|---------|---------|---------|
| `recharts` | v2.x | Charts for risk dashboard: expiry timelines, cert-by-grade distribution, algorithm breakdown | MIT |

**Why Recharts:** Composable, React-native, good TypeScript support. D3 is too low-level
for this use case. Chart.js requires a canvas context adapter in React. Recharts integrates
directly with React rendering.

### API Client

| Approach | Details |
|----------|---------|
| **OpenAPI codegen** | The Go server generates an OpenAPI 3.x spec at `/api/v1/openapi.json`. The TypeScript client is generated via `openapi-typescript` during build. No hand-written API calls in the frontend. |
| **Generator** | `openapi-typescript` + `openapi-fetch` (type-safe fetch wrapper) |

This ensures the frontend TypeScript types and the Go server types are always in sync.
When a Go API changes, the TypeScript client is regenerated — drift is caught at build time.

### Form Handling

| Library | Version | Purpose | License |
|---------|---------|---------|---------|
| `react-hook-form` | v7.x | Form state and validation | MIT |
| `zod` | v3.x | Schema validation (shared between form client-side validation and API request validation) | MIT |

### Explicitly Rejected Frontend Libraries

| Library | Why Rejected |
|---------|-------------|
| Material UI (MUI) | Heavy opinionated theming that conflicts with security tool aesthetics; large bundle |
| Ant Design | Chinese CDN dependencies, license uncertainty, heavy bundle |
| Redux Toolkit | Over-engineered for this use case; TanStack Query covers server state |
| Next.js | SSR adds complexity not needed for a self-hosted SPA dashboard; Vite + React SPA is sufficient |
| Axios | `openapi-fetch` + native `fetch` is sufficient; Axios is unnecessary overhead |

---

## 3. Database

### Primary Database

| Decision | Value |
|----------|-------|
| **Database** | PostgreSQL 16+ |
| **Driver** | `jackc/pgx/v5` |
| **Connection pooling** | `pgxpool` (included in pgx/v5) |
| **Migrations** | `golang-migrate/migrate/v4` with SQL files |
| **Schema approach** | Raw SQL migrations; no ORM |

**PostgreSQL-specific features used (in PostgreSQL repo implementation only):**
- `JSONB` for flexible metadata fields (`risk_flags`, `scan scope`, `template enrollment_permissions`)
- Declarative table partitioning for `audit_log` (partitioned by `RANGE(timestamp)`, monthly)
- `GIN` indexes on `JSONB` columns for risk flag queries
- `RETURNING` clause for efficient insert-and-fetch
- `pgcrypto` for server-side UUID generation (optional, can use app-level UUIDs)

### Development / Single-Node Database

| Decision | Value |
|----------|-------|
| **Database** | SQLite (via `mattn/go-sqlite3`) |
| **Mode** | Enabled by `KRYPTKEEPER_DB_MODE=sqlite` environment variable |
| **File location** | `$KRYPTKEEPER_DATA_DIR/kryptkeeper.db` (default: `/var/lib/kryptkeeper/`) |
| **WAL mode** | Enabled (`PRAGMA journal_mode=WAL`) for concurrent reads |
| **Limitations** | No `JSONB` operators (use `json_extract()` instead), no declarative partitioning, no parallel query |

**Repository pattern requirement (C-Tech04):** All database access goes through interfaces
defined in `internal/db/interface.go`. The PostgreSQL and SQLite implementations are in
separate packages. Business logic never imports `internal/db/postgres` or `internal/db/sqlite`
directly — only `internal/db`.

### Migration Strategy

Migrations use `golang-migrate` with SQL files in `internal/db/migrations/`:

```
internal/db/migrations/
  000001_initial_schema.up.sql
  000001_initial_schema.down.sql
  000002_add_risk_score_index.up.sql
  000002_add_risk_score_index.down.sql
```

Each migration file has a PostgreSQL version and a SQLite version where dialect differs:
```
internal/db/migrations/postgres/
internal/db/migrations/sqlite/
```

Migrations run automatically at server startup before the health endpoint becomes ready.
The `schema_migrations` table tracks applied versions.

---

## 4. Infrastructure and Deployment

### Container Runtime

| Decision | Value |
|----------|-------|
| **Container format** | OCI-compatible Docker images |
| **Build** | Multi-stage Dockerfile (builder stage: Go + Node; runtime stage: minimal `distroless/static`) |
| **Multi-arch** | `linux/amd64` and `linux/arm64` via `docker buildx` |
| **Registry** | `ghcr.io/bpmforge/kryptkeeper` |
| **Base image** | `gcr.io/distroless/static-debian12` (no shell, no package manager) |

**Why distroless:** Eliminates shell-based attack surface in the container. Trivy scans
report zero OS-level CVEs for distroless static images. Go static binaries run without
libc.

### Single-Node Deployment

| Tool | Version | Purpose |
|------|---------|---------|
| Docker Compose | v2.x | Single-node production and development stack |
| `postgres:16-alpine` | Official image | Bundled database for single-node |
| `nginx:1.25-alpine` | Official image | TLS termination and dashboard static file serving |

**Target:** `docker compose up` → working CA in under 15 minutes (C-Ops01).

### Kubernetes Deployment

| Tool | Version | Purpose |
|------|---------|---------|
| Helm | v3.x | Kubernetes packaging |
| CloudNativePG operator | v1.22.x | PostgreSQL operator (recommended; RDS/Cloud SQL also supported) |

Helm chart values expose: replica count, resource limits, ingress configuration, secret
references, OIDC configuration, and storage class selection.

### Reverse Proxy / TLS Termination

| Decision | Value |
|----------|-------|
| **Proxy** | nginx (single-node Docker) or Kubernetes Ingress (nginx-ingress or cloud LB) |
| **TLS** | Operator-provided certificate (or Let's Encrypt via cert-manager in Kubernetes) |
| **Cipher suites** | TLS 1.2+ minimum; recommended: TLS 1.3 only for dashboard, TLS 1.2+ for ACME compatibility |

---

## 5. Observability

### Metrics

| Decision | Value |
|----------|-------|
| **Library** | `prometheus/client_golang` |
| **Endpoint** | `GET /metrics` (Prometheus text format) |
| **Scrape target** | Prometheus or Grafana Agent |
| **Dashboards** | Pre-built Grafana dashboard JSON in `deployments/grafana/` |

**Key application metrics:**

| Metric Name | Type | Description |
|-------------|------|-------------|
| `kk_certificates_issued_total` | Counter | Certificates issued, labeled by CA and template |
| `kk_certificates_revoked_total` | Counter | Certificates revoked, labeled by reason code |
| `kk_ocsp_request_duration_seconds` | Histogram | OCSP response latency (P50/P95/P99) |
| `kk_discovery_scan_duration_seconds` | Histogram | Scan job duration by connector type |
| `kk_certificates_expiring` | Gauge | Certs expiring by threshold bucket (7d, 30d, 90d) |
| `kk_certificates_expired` | Gauge | Currently expired certificates in inventory |
| `kk_api_request_duration_seconds` | Histogram | REST API request latency by endpoint and status |
| `kk_db_query_duration_seconds` | Histogram | Database query latency by operation |

### Distributed Tracing

| Decision | Value |
|----------|-------|
| **Library** | `go.opentelemetry.io/otel` |
| **Protocol** | OTLP (gRPC or HTTP) |
| **Export** | Optional; configured via `OTEL_EXPORTER_OTLP_ENDPOINT` |
| **Propagation** | W3C Trace Context (`traceparent` header) |
| **Default** | Disabled (no telemetry without explicit configuration — C-Sec04) |

### Health Checks

| Endpoint | Purpose |
|----------|---------|
| `GET /health/live` | Liveness: process is running (returns 200 OK) |
| `GET /health/ready` | Readiness: database connected, migrations complete, required services reachable |

---

## 6. Testing

### Backend — Go

| Library / Tool | Version | Purpose | License |
|---------------|---------|---------|---------|
| `testing` (stdlib) | Go stdlib | All unit and integration tests | Go stdlib |
| `github.com/stretchr/testify` | v1.9.x | Assertions (`assert`, `require`), mock helpers | MIT |
| `github.com/stretchr/testify/mock` | (included) | Interface mocking for unit tests | MIT |
| SoftHSM2 | v2.x (system package) | PKCS#11 integration testing without real HSM hardware | BSD-2 |
| `github.com/testcontainers/testcontainers-go` | v0.28.x | PostgreSQL container for integration tests | MIT |

**Test strategy:**
- Unit tests: `*_test.go` alongside every `.go` file. Mock all external interfaces.
- Integration tests: `tests/integration/` directory. Use real PostgreSQL (testcontainers).
  Cover all enrollment protocols end-to-end (ACME order → certificate, EST simpleenroll, SCEP PKIOperation).
- PKCS#11 tests: SoftHSM2 configured in CI. Cover CA creation, signing, and key attribute queries.
- CI gate: `go test ./... -race` (race detector on all tests) must pass before merge.

**Coverage target:** 80% line coverage for `internal/ca` and `internal/enrollment`. Discovery
connectors are tested with recorded fixtures.

### Frontend — React

| Library / Tool | Version | Purpose | License |
|---------------|---------|---------|---------|
| `vitest` | v1.x | Unit and component tests (Vite-native, fast) | MIT |
| `@testing-library/react` | v14.x | React component testing (user interaction focus) | MIT |
| `@testing-library/user-event` | v14.x | User interaction simulation | MIT |
| `msw` (Mock Service Worker) | v2.x | API mocking for component tests | MIT |
| `@playwright/test` | v1.43.x | End-to-end browser tests | Apache 2.0 |

**E2E test targets:** Certificate issuance workflow, CA hierarchy creation, discovery scan
trigger and result view, alert routing configuration.

### Protocol Conformance Testing

| Tool | Purpose |
|------|---------|
| `certbot` / `acme.sh` | ACME client conformance against the ACME server |
| `openssl s_client` | EST and SCEP protocol testing |
| Wireshark captures | XCEP/WSTEP wire format validation (V2) |
| `openssl ocsp` | OCSP responder response validation |
| `openssl crl` | CRL format and revocation entry validation |

---

## 7. Build and Toolchain

### Build System

| Tool | Version | Purpose |
|------|---------|---------|
| `go build` | Go 1.24 | Backend binary compilation |
| `vite build` | v5.x | Frontend production build |
| `docker buildx` | v0.12.x | Multi-arch container image builds |
| `make` | System | Top-level build targets (`make build`, `make test`, `make docker`) |

**Static binary flags:** `go build -ldflags="-s -w" -trimpath` — strips debug symbols
and source paths. Required for agent size budget. UPX compression optional if budget exceeded.

### Linting and Formatting

| Tool | Version | Purpose |
|------|---------|---------|
| `golangci-lint` | v1.57.x | Go linting (includes `staticcheck`, `errcheck`, `gosec`, `govet`) | MIT |
| `gofmt` / `goimports` | Stdlib | Code formatting (enforced in CI) | |
| `eslint` | v8.x | TypeScript/React linting | MIT |
| `prettier` | v3.x | TypeScript/CSS formatting | MIT |

**`golangci-lint` enabled linters:**
- `errcheck` — unchecked error returns
- `gosec` — security-sensitive patterns (G107: URL injection, G401: weak crypto, etc.)
- `staticcheck` — deep static analysis
- `govet` — alignment, shadow variable detection
- `exhaustive` — exhaustive enum switches
- `noctx` — HTTP requests without context

### Dependency Management

| Tool | Purpose |
|------|---------|
| `go mod tidy` | Dependency cleanup (run in CI) |
| `go-licenses` | License scanning for all Go dependencies (Apache 2.0 boundary enforcement — C-Tech05) |
| `pnpm audit` | Frontend dependency vulnerability scanning |
| `govulncheck` | Go vulnerability database check against used packages |

---

## 8. Security Tooling

| Tool | Purpose | When Run |
|------|---------|----------|
| `govulncheck` | Go vulnerability database scan | CI on every PR |
| `trivy` | Container image vulnerability scan | CI on every image build |
| `osv-scanner` | OSV database scan for all dependencies | CI on every PR |
| `go-licenses` | License compatibility check (C-Tech05) | CI on every PR |
| `gosec` (via golangci-lint) | Go source security patterns | CI on every PR |
| `semgrep` (optional) | Custom security rules (e.g., no `math/rand` for crypto) | CI |
| Snyk or Dependabot | Automated dependency update PRs | Weekly |

---

## 9. Version Compatibility Matrix

| Component | Minimum Version | Target Version | Notes |
|-----------|----------------|----------------|-------|
| Go | 1.23 | 1.24 | 1.24 for hybrid PQC TLS; 1.21+ for `log/slog` |
| PostgreSQL | 14 | 16 | 14 for declarative partitioning; 16 for latest performance |
| SQLite | 3.35 | 3.45 | 3.35 for `RETURNING` clause support |
| React | 18.0 | 18.3 | 18 for concurrent features and Suspense |
| Node.js (build only) | 20 LTS | 22 LTS | Build-time only; not a runtime dependency |
| Docker / Podman | 24 / 4 | Latest | Multi-arch build requires `buildx` |
| Kubernetes | 1.27 | 1.29 | 1.27 for stable cert-manager CRDs |
| nginx | 1.24 | 1.25 | For TLS 1.3 and modern cipher suite support |
| SoftHSM2 | 2.6 | 2.6 | For PKCS#11 CI testing |
| Prometheus | 2.40 | 2.50 | Metrics scraping |

---

## 10. Dependency License Summary

All Go and npm dependencies in the Apache 2.0 core MUST pass the license check in CI.

**Allowed licenses in core:**

| License | Examples | Permitted |
|---------|---------|-----------|
| Apache 2.0 | `prometheus/client_golang`, `spf13/cobra`, Cloudflare CIRCL | Yes |
| MIT | `go-chi/chi`, `jackc/pgx`, `stretchr/testify`, `shadcn/ui`, `tailwindcss` | Yes |
| BSD-2 | `mattn/go-sqlite3`, `google/uuid` | Yes |
| BSD-3 | `golang.org/x/*`, `crypto11` | Yes |
| ISC | `lucide-react` | Yes |
| MPL-2.0 | `golang-migrate` | Yes (with care — file-level copyleft, not project-level) |

**Not permitted in core:**

| License | Examples | Status |
|---------|---------|--------|
| LGPL | Many Java libraries | Rejected |
| GPL-2, GPL-3 | Many Unix tools | Rejected |
| AGPL | Many SaaS tools | Rejected — enterprise legal blocker |
| BSL | CockroachDB, some HashiCorp | Rejected |
| SSPL | MongoDB | Rejected |
| EUPL | Some European government projects | Rejected |

**Enforcement:** `go-licenses check ./...` runs in CI with a deny list for prohibited
licenses. Any new dependency that introduces a non-permitted license fails the CI gate.
