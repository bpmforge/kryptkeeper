# Kryptkeeper

[![ci-main](https://github.com/bpmforge/kryptkeeper/actions/workflows/ci-main.yml/badge.svg)](https://github.com/bpmforge/kryptkeeper/actions/workflows/ci-main.yml)
[![Release](https://github.com/bpmforge/kryptkeeper/actions/workflows/release.yml/badge.svg)](https://github.com/bpmforge/kryptkeeper/actions/workflows/release.yml)
[![Agent CI](https://github.com/bpmforge/kryptkeeper/actions/workflows/agent-build.yml/badge.svg)](https://github.com/bpmforge/kryptkeeper/actions/workflows/agent-build.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/bpmforge/kryptkeeper)](https://goreportcard.com/report/github.com/bpmforge/kryptkeeper)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

> Guard your cryptographic trust

Kryptkeeper is an open-source enterprise PKI and Crypto Trust Platform. It gives security teams complete visibility and control over their certificate infrastructure — from a full Certificate Authority to certificate lifecycle management, built-in discovery scanning, and a native ADCS replacement — all under the Apache 2.0 license.

**Key differentiators vs step-ca and EJBCA:**
- OCSP responder free in OSS (step-ca withholds it)
- Built-in certificate discovery — network scanning, WinRM agentless, CT log monitoring (agentless SSH certificate discovery is planned, not yet wired)
- Native MS-XCEP + MS-WSTEP server (first open-source ADCS replacement)
- PQC-ready architecture (ML-DSA via FIPS 204)

---

## Quick Start

**Prerequisites:** Docker + Docker Compose, or Go 1.26+ for local development.

```bash
git clone https://github.com/bpmforge/kryptkeeper.git
cd kryptkeeper
cp env.example .env
# Edit .env: set APP_BOOTSTRAP_TOKEN and KRYPTKEEPER_KEYSTORE_PASSPHRASE
# (compose refuses to start without either; they must be different values).
# Generate each with: openssl rand -hex 32
# env.example already sets KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true so the first
# boot creates the hub's default root CA.
docker compose up -d
```

Compose defaults to SQLite, so no database password is needed. `POSTGRES_PASSWORD`
only matters if you enable the optional Postgres profile in
`docker-compose.override.yml`. `APP_JWT_HS256_SECRET` is only needed for
`AUTH_MODE=jwt` (at least 32 bytes).

The dashboard is at **http://localhost:3000**. The API listens on
**https://localhost:8080/api/v1** — Compose enables TLS by default
(`KRYPTKEEPER_TLS_DISABLE=false`, `KRYPTKEEPER_BASE_URL=https://localhost:8080`)
and writes the hub's CA certificate (no key material) to the `tls-trust`
volume. Export it once and pass it to `curl` or any client:

```bash
docker run --rm -v kryptkeeper_tls-trust:/trust:ro alpine cat /trust/ca.pem > ca.pem
curl --cacert ca.pem https://localhost:8080/healthz
```

To opt out of TLS entirely for local experimentation, set
`KRYPTKEEPER_TLS_DISABLE=true` in `.env` and use `http://localhost:8080`
instead — see [`docs/deployment.md`](docs/deployment.md) for the full TLS
story.

### First run: issue your first certificate

On first start the hub creates a default root CA, "Kryptkeeper Root CA"
(`KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true` is set in `env.example`; it only acts
when no CA exists, so it is safe to leave set). The hub needs a CA at boot to
issue its own TLS listener certificate — without one it exits with `no CA
configured`. Set `KRYPTKEEPER_CA_NAME` in `.env` before the first start to
rename that root.

Use the `APP_BOOTSTRAP_TOKEN` value from `.env` as the bearer token. Nothing
generates or logs one for you; after SSO/login is configured you can turn it
off with `KRYPTKEEPER_DISABLE_BOOTSTRAP_TOKEN=true`.

```bash
export TOKEN=<your APP_BOOTSTRAP_TOKEN>
API=https://localhost:8080/api/v1
auth=(--cacert ca.pem -H "Authorization: Bearer $TOKEN")

# 1. Find the default root CA's id
curl "${auth[@]}" $API/cas
#    -> note data[0].id as <ca-id>

# 2. (Optional) create another root CA instead — subject_cn is the only
#    required field
curl "${auth[@]}" -X POST $API/cas -H "Content-Type: application/json" \
  -d '{"name": "My Root CA", "type": "root", "subject_cn": "My Root CA", "algorithm": "ECDSA-P256"}'

# 3. Create a certificate template — a fresh install has none, and issuance
#    requires template_id
curl "${auth[@]}" -X POST $API/templates -H "Content-Type: application/json" -d '{
  "name": "tls-server",
  "display_name": "TLS Server (90 days)",
  "key_usage": ["digitalSignature"],
  "extended_key_usage": ["serverAuth"],
  "allowed_algorithms": ["ECDSA", "RSA"],
  "validity_period": "P90D",
  "active": true
}'
#    -> note data.id as <template-id>

# 4. Generate a key and CSR. Issuance is CSR-in: you keep the private key,
#    Kryptkeeper only ever sees the CSR.
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout server.key -out server.csr -subj "/CN=app.example.com" \
  -addext "subjectAltName=DNS:app.example.com"

# 5. Issue the certificate (jq -Rs JSON-encodes the multi-line CSR)
jq -n --arg ca "<ca-id>" --arg tpl "<template-id>" --rawfile csr server.csr \
  '{ca_id: $ca, template_id: $tpl, csr_pem: $csr}' |
curl "${auth[@]}" -X POST $API/certificates -H "Content-Type: application/json" -d @-
#    -> note data.fingerprint_sha256 as <fingerprint>

# 6. Download the leaf, and the CA certificate to trust it
curl "${auth[@]}" "$API/certificates/<fingerprint>/download?format=pem" -o leaf.pem
curl "${auth[@]}" "$API/cas/<ca-id>/chain?format=pem" -o root.pem

# 7. Verify
openssl verify -CAfile root.pem leaf.pem
```

`/cas/{id}/chain?format=pem` returns the CA's public certificate followed by its
parents up to the root (for a root CA, just the root) — import it into a trust
store or pass it to `openssl verify -CAfile`. Without `format=pem` it returns
chain metadata as JSON.

`.../download?format=pem&include_chain=true` returns the conventional
"fullchain": the leaf plus any issuing intermediates, **excluding** the root.
A leaf issued directly by a root is therefore a single certificate either way;
fetch the root from `/cas/{id}/chain?format=pem` as above.

### ACME (certbot / acme.sh)

```bash
# Point your ACME client at the built-in ACME server (pass --cacert ca.pem
# equivalent for your client, or KRYPTKEEPER_TLS_DISABLE=true for plain HTTP)
certbot certonly \
  --server https://localhost:8080/acme/directory \
  --standalone \
  -d api.example.com
```

---

## Configuration

All configuration is via environment variables. See `env.example` for the full list.
Note: `APP_BIND_ADDR` is a host only (default `127.0.0.1`) and `PORT` is the
port (default `8080`) — they are joined to form the listen address.

| Variable | Required | Description |
|----------|----------|-------------|
| `APP_JWT_HS256_SECRET` | Yes (jwt mode) | HS256 secret for JWT auth; startup fails below 32 bytes (`openssl rand -hex 32`) |
| `POSTGRES_PASSWORD` | Only with the Compose Postgres profile | PostgreSQL password |
| `AUTH_MODE` | No | `bootstrap` (default), `jwt`, or `oidc` |
| `APP_BOOTSTRAP_TOKEN` | **Yes** | Admin token — Compose refuses to start without it; it is not auto-generated. Use 32+ characters; `KRYPTKEEPER_DISABLE_BOOTSTRAP_TOKEN=true` turns it off |
| `APP_AUTH_ROLE_CLAIM`, `APP_AUTH_ROLE_MAP_JSON` | No | Map a jwt/oidc token claim to a role; unmapped bearer tokens are read-only `viewer` (see `docs/ops/OIDC_JWKS_RUNBOOK.md` section 7) |
| `APP_CERTS_SUMMARY_PROVIDER` | No | `file` (default) or `db` |
| `APP_NOTIFICATION_PROVIDER` | No | `file` (code default when unset; dev stub), `db` (records deliveries but does **not** send; the renewal scheduler skips alerts and audits them as `skipped`) or `delivery` (Compose default; sends via SMTP, Slack, PagerDuty or webhook and persists alert rules) |
| `KRYPTKEEPER_RENEWAL_RULE_SEND_CAP` | No | Most notification-rule alerts one renewal scan processes (default 500); the rest roll to the next scan |
| `APP_USER_PROVIDER` | No | `db` (default) or `file`/`memory` — in-memory, lists nothing and does not persist; tests and offline dev only |
| `KRYPTKEEPER_DB_MODE` | No | `sqlite` (default) or `postgres` |
| `KRYPTKEEPER_DB_DSN` / `DATABASE_URL` | If postgres | PostgreSQL connection string |
| `KRYPTKEEPER_KEY_BACKEND` | No | `software` (default, PKCS#8), `pkcs11`, `cloudkms` (with `KRYPTKEEPER_KMS_PROVIDER=aws\|gcp\|azure`), `vault` — see [Key Storage](#key-storage) for maturity |
| `KRYPTKEEPER_KEYSTORE_PASSPHRASE` | **Yes** (software keystore) | Encrypts CA private keys at rest; required by Compose and must differ from `APP_BOOTSTRAP_TOKEN` |
| `KRYPTKEEPER_ALLOW_MISSING_CA_KEYS` | No | Recovery only: start even though an active CA has no key in the keystore (default: the hub refuses to start) |
| `KEYSTORE_SIGNER_TTL_MINUTES` | No | Idle eviction for decrypted CA signers (default 60) |
| `SIEM_WEBHOOK_URL` | No | Push cert lifecycle events to a webhook |
| `SIEM_SYSLOG_ADDR` | No | RFC 5424 syslog output (Splunk/QRadar) |
| `APP_VERSION` | No | Version string shown in `/api/v1/meta` |

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Kryptkeeper                         │
│                                                     │
│  ┌──────────┐  ┌──────────┐  ┌───────────────────┐ │
│  │ Dashboard│  │  REST    │  │  Protocol Servers  │ │
│  │(React/TS)│  │  API     │  │ ACME OCSP CRL      │ │
│  │  :3000   │  │  :8080   │  │ EST  SCEP XCEP     │ │
│  └──────────┘  └──────────┘  └───────────────────┘ │
│                     │                               │
│  ┌──────────────────▼──────────────────────────┐   │
│  │              CA Engine                       │   │
│  │  Root CA → Issuing CA → Certificate          │   │
│  │  Templates · Revocation · OCSP/CRL          │   │
│  └──────────────────────────────────────────┬──┘   │
│                                             │       │
│  ┌──────────────────────────────────────────▼──┐   │
│  │              Storage Layer                   │   │
│  │  PostgreSQL · SQLite · PKCS#8 · PKCS#11     │   │
│  │  AWS KMS · GCP KMS · Azure Key Vault        │   │
│  └─────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

**Single binary deployment.** The CA core, API server, and all protocol endpoints run in one Go binary. The dashboard is a compiled React app served separately.

---

## Enrollment Protocols

| Protocol | RFC | Use case |
|----------|-----|----------|
| ACME | 8555 | TLS certs for web servers, certbot/acme.sh |
| EST | 7030 | Enterprise device enrollment |
| SCEP | — | Device enrollment; validated with micromdm/scep and openssl. Network-device interop (F5, Citrix, Palo Alto) is untested |
| OCSP | 5019 | Real-time revocation checking |
| CRL | 5280 | Certificate Revocation Lists |
| MS-XCEP | — | Windows auto-enrollment (V2) |
| MS-WSTEP | — | Windows certificate issuance (V2) |
| CMP | 4210 | Certificate Management Protocol |

---

## API Reference

The full OpenAPI 3.1 spec is at [`docs/openapi.yaml`](docs/openapi.yaml).

**Base URL:** `https://localhost:8080/api/v1` (TLS by default; `http://` only
when `KRYPTKEEPER_TLS_DISABLE=true`)

**Authentication:** Pass `Authorization: Bearer <token>` on every request (except `/meta` and `/auth/login`). Tokens can be:
- Bootstrap token (the `APP_BOOTSTRAP_TOKEN` you configured; not auto-generated or logged)
- JWT (HS256, when `AUTH_MODE=jwt`)
- OIDC token (RS256, when `AUTH_MODE=oidc`)
- API key (`kk_<kid>_<secret>`, created via `POST /api/v1/api-keys`)

**Core endpoints:**

```
GET    /meta                      — service health and version
POST   /auth/login                — login with email + password
POST   /auth/logout               — expire session cookie
GET    /authz-check               — verify current token + get role

GET    /cas                       — list CAs
POST   /cas                       — create root or intermediate CA
GET    /cas/{id}                  — get CA detail
PATCH  /cas/{id}                  — update CA metadata
POST   /cas/{id}/activate         — activate a suspended CA
POST   /cas/{id}/suspend          — suspend a CA

GET    /certificates              — list certificates (filter, paginate)
POST   /certificates              — issue a certificate
POST   /certificates/{fp}/renew   — renew a certificate
POST   /certificates/{fp}/revoke  — revoke a certificate
POST   /certificates/import       — import an external certificate

GET    /templates                 — list certificate templates
POST   /templates                 — create a template
PUT    /templates/{id}            — update a template
DELETE /templates/{id}            — delete a template

GET    /discovery/endpoints       — list discovered endpoints
POST   /discovery/scans           — queue a discovery scan
GET    /discovery/scan-jobs       — list scan jobs

GET    /notifications/summary     — notification health summary
GET    /notifications/deliveries  — delivery queue
GET    /notifications/rules       — list alert rules
POST   /notifications/rules       — create an alert rule
PUT    /notifications/rules/{id}  — update a rule
DELETE /notifications/rules/{id}  — delete a rule

GET    /users                     — list users
POST   /users/invite              — invite a user
PATCH  /users/{id}                — change role or status
DELETE /users/{id}                — deactivate a user

GET    /audit                     — audit log (filter, paginate)
GET    /search                    — cross-inventory search

PATCH  /certificates/{fp}/ownership — set owner email/team/service/labels
POST   /certificates/bulk-revoke  — bulk revoke (≤500 certs)
POST   /certificates/bulk-reissue — bulk re-issue (≤200 certs)

GET    /approvals                 — pending approval requests
POST   /approvals/{id}/approve    — approve a pending request
POST   /approvals/{id}/reject     — reject a pending request

POST   /keys/{id}/rotate          — rotate a CA key
POST   /keys/{id}/export          — passphrase-wrapped key backup
POST   /keys/import               — restore a key from backup

GET    /reports/ca-health         — CA health report
GET    /reports/expiry-timeline   — expiry calendar by CA/team/owner
GET    /reports/revocation-activity — revocations in a window
GET    /reports/issuance-velocity — certs/day by CA and requester
GET    /reports/change-audit      — full lifecycle history per cert
GET    /reports/compliance-evidence — SOC 2 / PCI DSS evidence pack
GET    /reports/algorithm-sunset  — post-2030 non-compliant certs
```

---

## Key Storage

| Layer | Provider | Status |
|-------|----------|--------|
| 1 | Encrypted PKCS#8 PEM (Argon2id KDF) | Default; used by every test harness |
| 2 | PKCS#11 HSM via ThalesGroup/crypto11 | Tested on SoftHSM2; no vendor HSM tested |
| 3 | AWS KMS, Azure Key Vault | Validated against emulators only (moto, Lowkey Vault); not tried against real cloud accounts |
| 4 | HashiCorp Vault transit, GCP Cloud KMS | Experimental (untested) |

All signing goes through Go's `crypto.Signer` interface — swapping providers never changes CA logic.

---

## Issuing post-quantum (ML-DSA) certificates

Any CA (classical or ML-DSA) can issue a certificate for an ML-DSA-44/65/87
(FIPS 204) key. Send a PKCS#10 request as `csr_pem` to
`POST /api/v1/certificates` (or `.../{fingerprint}/renew`). With OpenSSL 3.5+:

```bash
openssl genpkey -algorithm ML-DSA-65 -out leaf.key
openssl req -new -key leaf.key -subj "/CN=svc.example.com" \
  -addext "subjectAltName=DNS:svc.example.com" -out leaf.csr
```

The standard `CERTIFICATE REQUEST` PEM label is accepted: the hub reads the
public-key algorithm OID in the request and, for ML-DSA, verifies the
request's self-signature itself (the Go standard library cannot). The
legacy `ML-DSA CERTIFICATE REQUEST` label still works, as does
`HYBRID CERTIFICATE REQUEST`. A request whose signature does not verify, or
whose key type is unsupported, returns `400`; an inactive or keyless issuing
CA returns `409`.

ML-DSA requests are accepted on the REST API (`/api/v1/certificates`).
The EST, SCEP and ACME endpoints enroll classical (RSA/ECDSA) keys only.

---

## Development

```bash
# Backend (Go)
go build ./...
go test ./...

# Frontend (React/TypeScript)
cd ui && npm install && npm run dev
npm run build       # production build
npm run test        # vitest

# Backend against local SQLite
# (backend) go run ./cmd/kryptkeeper — see env.example for required vars
```

**Environment:** Go 1.26+ (go.mod), Node 24 (`ui/.nvmrc`), PostgreSQL 16 or SQLite. Postgres support is backed by round-trip tests for every database-backed store (gated on `KRYPTKEEPER_TEST_POSTGRES_DSN`; CI runs them with `-p 1`).

### Live-Postgres integration tests

`internal/db`'s `TestRunMigrations_Postgres*` tests replay the full migration
suite against a real PostgreSQL instance instead of SQLite. They are skipped
unless `KRYPTKEEPER_TEST_POSTGRES_DSN` is set:

```bash
KRYPTKEEPER_TEST_POSTGRES_DSN="postgres://postgres:changeme@localhost:5432/kryptkeeper_test?sslmode=disable" \
  go test ./internal/db/... -run TestRunMigrations_Postgres
```

**`KRYPTKEEPER_TEST_POSTGRES_DSN` must point at a disposable database —
never a shared or production one, and never the `docker-compose.override.yml`
`postgres` service (that one backs a real dev deployment, not a throwaway).**
Every one of these tests drops and recreates the target database's entire
`public` schema before it runs, so each test starts from a known-empty state
regardless of what an earlier run left behind (including a run with
`KRYPTKEEPER_SEED_CI_DATA=true`, which would otherwise leave a recorded
migration that makes every later default run fail). Point it at its own
throwaway container instead, e.g.:

```bash
podman run -d --name kk-test-pg -e POSTGRES_PASSWORD=changeme \
  -e POSTGRES_DB=kryptkeeper_test -p 55432:5432 postgres:16-alpine
```

---

## Deployment

### Docker Compose (recommended for single-node)

```bash
docker compose up -d
```

### Kubernetes (Helm)

The chart does not bundle PostgreSQL: bring an external database and pass its
connection string. The bootstrap token and keystore passphrase must be different
values (`openssl rand -hex 32` for each).

```bash
helm install kryptkeeper charts/kryptkeeper \
  --set secrets.bootstrapToken=<bootstrap-token> \
  --set secrets.keystorePassphrase=<keystore-passphrase> \
  --set secrets.databaseURL='postgres://user:password@db.example.internal:5432/kryptkeeper?sslmode=require' \
  --set ingress.enabled=true \
  --set 'ingress.hosts[0].host=pki.example.com' \
  --set 'ingress.hosts[0].paths[0].path=/' \
  --set 'ingress.hosts[0].paths[0].pathType=Prefix'
```

For production, create a Secret yourself and set `secrets.existingSecret`
instead of passing values inline. The chart renders with `helm template`, but
it has not been install-tested on a cluster (beta).

### Binary

```bash
go build -o kryptkeeper ./cmd/kryptkeeper
APP_BOOTSTRAP_TOKEN=<bootstrap-token> \
KRYPTKEEPER_KEYSTORE_PASSPHRASE=<keystore-passphrase> \
KRYPTKEEPER_DB_MODE=sqlite ./kryptkeeper
```

For `AUTH_MODE=jwt`, also set `APP_JWT_HS256_SECRET` (at least 32 bytes).

---

## Security

- The management API requires authentication (except `/meta` and `/auth/login`). Protocol endpoints authenticate per protocol (ACME accounts, EST users, SCEP challenges, CMP shared secret, Kerberos for WSTEP/XCEP); OCSP, CRL and the ACME directory are public by design
- Session tokens stored as httpOnly cookies — not exposed to JavaScript
- CSRF protection via `SameSite=Strict` cookie policy + Bearer token auth
- Rate limiting on ACME, OCSP, CRL, EST, SCEP, CMP, WSTEP, and XCEP endpoints (per-IP sliding window)
- Audit log records every action with actor, resource, outcome, and trace ID
- Fail-closed startup: unknown auth mode, missing secrets, or invalid config causes immediate exit

Report security issues to the project maintainers privately before public disclosure.

---

## Roadmap

Kryptkeeper's internal milestones v1.0 through v2.2 (tags `internal/v1.0.0` to
`internal/v2.2.0`; never publicly released — v0.9.0 is the first public release)
delivered the full CA engine and protocols, compliance
reporting, renewal autopilot, audit-ready evidence packs, PQC migration
copilot, AI-native MCP operations, SPIFFE/SVID, and flag-gated
multi-tenancy), then pivoted to an estate-management direction — see
[`docs/DECISIONS.md`](docs/DECISIONS.md) D-106 and
[`docs/sdlc/phase-0-ideation/VISION_V5.md`](docs/sdlc/phase-0-ideation/VISION_V5.md)
for the full strategy. For where that work stands today, see
[`docs/ROADMAP.md`](docs/ROADMAP.md) for the current wave plan and
[`docs/NEXT_HORIZON.md`](docs/NEXT_HORIZON.md) for what comes after it.
[`CHANGELOG.md`](CHANGELOG.md) is the log of what has
actually shipped.

---

## Validation status

Results from 2026-10-11 on v0.9.0-rc.7 (`main` at `2f9e766`) against real clients (full table in
[`docs/release/LIVE_RESULTS_v0.9.md`](docs/release/LIVE_RESULTS_v0.9.md); per-feature status in
[`docs/release/FEATURE_VALIDATION_v0.9.md`](docs/release/FEATURE_VALIDATION_v0.9.md)):

| Suite | Result | Real peer |
|-------|--------|-----------|
| Smoke (`tests/smoke`) | 331/331 | hub binary, curl |
| ACME (`tests/live/acme`) | 28/28 | certbot, lego |
| Protocols (`tests/live/protocols`) | all steps passed | openssl EST/SCEP/CMP/OCSP/CRL |
| TLS (`tests/live/tls`) | all steps passed | globalsign/est |
| SSH CA (`tests/live/sshca`) | all steps passed | OpenSSH |
| Autopilot (`tests/live/autopilot`) | all pass (29 checks) | nginx hosts and the agent |
| Agent (`tests/live/agent`) | 18/18 | Linux container agent |
| SSH install (`tests/live/ssh-install`) | all pass (nginx, apache, rollback) | OpenSSH, nginx, apache |
| Plugins (`tests/live/plugins`) | all steps passed (27 checks) | example plugin, mock appliance |

Upgrade test: full matrix on rc.5, spot-check on rc.7 (schema 76); see
[`docs/release/UPGRADE_TEST_v0.9.md`](docs/release/UPGRADE_TEST_v0.9.md). Older dated runs
(Kubernetes, mesh, notifications, PKCS#11, WSTEP/XCEP) are recorded in
[`docs/UAT_PLAN.md`](docs/UAT_PLAN.md) and were not re-run on 2026-10-11.

## Status of features in v0.9

- **Validated against real clients:** CA and issuance, ACME (http-01), EST, SCEP, CMP, OCSP/CRL,
  WSTEP/XCEP (Windows lab), SSH CA, agent, SSH/Kubernetes install (SSH install only; SSH certificate discovery is not wired), notifications, PKCS#11 (SoftHSM2).
- **Beta (works; unit/integration-tested only):** reports, compliance evidence, CBOM and PQC
  readiness; renewal autopilot, rollout groups and PQC waves; SAML/OIDC/SCIM (tested against
  in-process IdPs); CT monitoring; cloud inventory; ADCS sync; Terraform provider; air-gap bundle;
  MCP server; Helm chart.
- **Experimental:** multi-tenancy (see below); HashiCorp Vault and GCP Cloud KMS keystores.
- **Not in v0.9:** agentless SSH certificate discovery (the scanner exists but nothing calls it yet); finding exceptions/risk acceptance (v0.10); issuer connectors other than
  `internal` and ACME (DigiCert, EST, SCEP and WSTEP upstream connectors).
- **Plugins:** the F5 and Citrix delivery plugins are verified against mock APIs only, not real
  appliances.

---

## Multi-tenancy (experimental)

Multi-tenancy (`MULTI_TENANCY=on`) is **experimental in v0.9**: tenant isolation is not a
security boundary, and a tenant admin can act across tenants. The hub refuses to start with it
on unless `KRYPTKEEPER_MULTI_TENANCY_EXPERIMENTAL=accept-risk` is set. Known gaps and the v0.10
plan: [docs/design/TENANCY_POSTURE.md](docs/design/TENANCY_POSTURE.md).

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

The core CA engine, all protocol servers, certificate discovery, and the management dashboard are free and open-source under Apache 2.0.
