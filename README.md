# Kryptkeeper

[![ci-main](https://github.com/bpmforge/kryptkeeper/actions/workflows/ci-main.yml/badge.svg)](https://github.com/bpmforge/kryptkeeper/actions/workflows/ci-main.yml)
[![Release](https://github.com/bpmforge/kryptkeeper/actions/workflows/release.yml/badge.svg)](https://github.com/bpmforge/kryptkeeper/actions/workflows/release.yml)
[![Agent CI](https://github.com/bpmforge/kryptkeeper/actions/workflows/agent-build.yml/badge.svg)](https://github.com/bpmforge/kryptkeeper/actions/workflows/agent-build.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/bpmforge/kryptkeeper)](https://goreportcard.com/report/github.com/bpmforge/kryptkeeper)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Kryptkeeper is a self-hosted certificate authority and certificate lifecycle manager. It can replace Active Directory Certificate Services (AD CS) or run beside it. It also manages certificates that other CAs issued: it finds them, assigns owners, renews them through their own CA or yours, and installs them on the servers that use them, with verify and rollback. It is one Go binary and works offline. Apache 2.0.

**As a CA:**
- Root and issuing CAs, templates, revocation, and OCSP and CRL responders
- Enrollment over ACME, EST, SCEP, CMP and MS-XCEP/MS-WSTEP (Windows autoenrollment), plus Intune SCEP
- An AD CS importer and a cutover path, so you can run beside AD CS first and move over later

**As a lifecycle manager, for certificates from any CA:**
- Inventory from network scans, CT log monitoring, agentless WinRM and SSH discovery, an AD CS sync, cloud certificate services and bulk import
- Each certificate marked managed, externally managed or unmanaged, with an owner and a risk score
- Renewal through the issuing CA (any ACME CA, SCEP, EST, Vault PKI, EJBCA and the commercial-CA connectors) or through a Kryptkeeper CA (see [Use your existing CA](#use-your-existing-ca))
- Install, verify and rollback on IIS, nginx, Apache, HAProxy, Tomcat and Kubernetes Secrets, with approvals and an append-only audit log
- Expiry alerts to email, webhooks, Slack, PagerDuty and more

It also has a PQC migration copilot, an SSH certificate authority, an MCP server, SPIFFE support and flag-gated multi-tenancy. They are described lower down.

## Project status

I am the only maintainer (@bpmforge). I have worked on PKI, key management and security architecture for more than 13 years: at a security vendor, an IT services firm and a cloud provider. I build Kryptkeeper with heavy use of Claude Code. I design the features, run every lab test listed in this repository and review what ships.

There has been no external penetration test yet. The OpenSSF Scorecard score is 4.6 out of 10 as of October 2026.

Among the public ACME CA and DNS presets, only Let's Encrypt staging and Cloudflare DNS-01 have run live.

Development happens in a private repository. This public repository gets a signed snapshot per release, so lab records cite development commit hashes.

---

## What's proven, and where

Every line below points at a dated record in [`docs/release/`](docs/release/). If there is no record, we do not call it proven. The release gate and lab sweep for 1.0.0 are in [`LIVE_RESULTS_v1.0.0.md`](docs/release/LIVE_RESULTS_v1.0.0.md); the 1.1 records are listed at the end of [`RELEASE_NOTES_v1.1.0.md`](docs/release/RELEASE_NOTES_v1.1.0.md).

- **Protocols and CA:** ACME, EST, SCEP, CMP, OCSP and CRL ran against real clients in the 1.0.0 lab pass ([`LIVE_RESULTS_v1.0.0.md`](docs/release/LIVE_RESULTS_v1.0.0.md)). SCEP from F5 and Palo Alto appliances has not been run.
- **Windows:** GPO autoenrollment, WSTEP renewal and IIS push passed on Windows 11 25H2 and Server 2022 ([`LIVE_RESULTS_v1.0.0.md`](docs/release/LIVE_RESULTS_v1.0.0.md), [`LIVE_RESULTS_v1_WINDOWS.md`](docs/release/LIVE_RESULTS_v1_WINDOWS.md)). A new Server 2025 member enrolled the same way, and all three accepted the 1.1 key-usage profile with chains validating ([`LIVE_RESULTS_WINDOWS_KU_WS2025_v1.1.md`](docs/release/LIVE_RESULTS_WINDOWS_KU_WS2025_v1.1.md)). Windows 10 and Server 2019 were not tested.
- **AD CS cutover:** a rehearsal against a live AD CS on Windows Server 2025 passed all six steps of the [cutover playbook](docs/guides/replace-adcs.md): live inventory sync, template import, takeover of a domain-joined Windows 11 machine, re-sync and revert ([`ADCS_CUTOVER_REHEARSAL_v0.21.md`](docs/release/ADCS_CUTOVER_REHEARSAL_v0.21.md)).
- **Install, verify and rollback:** agentless SSH installs passed 43 of 43 checks on nginx, Apache, HAProxy and Tomcat ([`LIVE_RESULTS_SSH_INSTALL_v0.15.md`](docs/release/LIVE_RESULTS_SSH_INSTALL_v0.15.md)), and IIS push, verify and rollback passed in the 1.0.0 lab pass ([`LIVE_RESULTS_v1.0.0.md`](docs/release/LIVE_RESULTS_v1.0.0.md)).
- **Renewal at another CA:** SCEP and EST renewal ran against independent CA servers ([`LIVE_RESULTS_UPSTREAM_RENEW_v0.15.md`](docs/release/LIVE_RESULTS_UPSTREAM_RENEW_v0.15.md)); ACME renewal at Let's Encrypt staging with Cloudflare DNS-01, followed by SSH install and verify, passed in the 1.0.0 lab pass and again on 1.1.0 ([`LIVE_RESULTS_v1.0.0.md`](docs/release/LIVE_RESULTS_v1.0.0.md), [`LIVE_RESULTS_v1.1.0_REGRESSION.md`](docs/release/LIVE_RESULTS_v1.1.0_REGRESSION.md)).
- **Day-one estate picture:** on a new Ubuntu VM, a bulk import, a network scan and an AD CS export from a real enterprise CA became one risk-scored estate of 29 certificates, with the estate report, dashboard and seeded counts in agreement. Following the docs as written took 19 minutes and hit five defects in the docs, the Dockerfile and the script; all five are fixed, and a rerun from an empty hub passed with no workarounds ([`DAY_ONE_RUN_v1.1.md`](docs/release/DAY_ONE_RUN_v1.1.md)).
- **Discovery:** TLS, protocol and agentless SSH certificate discovery passed on real sshd and seeded endpoints ([`LIVE_RESULTS_v1.0.0.md`](docs/release/LIVE_RESULTS_v1.0.0.md), [`LIVE_INVENTORY_v1.md`](docs/release/LIVE_INVENTORY_v1.md)).
- **Single sign-on:** OIDC, SAML and SCIM passed 39 of 39 checks against a real Keycloak 26 container ([`LIVE_RESULTS_KEYCLOAK_v0.21.md`](docs/release/LIVE_RESULTS_KEYCLOAK_v0.21.md)). We have not tested other identity providers.
- **Key storage:** PKCS#11 on SoftHSM2, and Vault transit against a Vault dev server, passed ([`LIVE_RESULTS_v1.0.0.md`](docs/release/LIVE_RESULTS_v1.0.0.md)). AWS KMS, Azure Key Vault and GCP Cloud KMS passed against emulators only. No vendor HSM and no real cloud KMS account has been tried.
- **Kubernetes:** the Helm chart installed on kind, and the two-replica failover and drain tests passed on kind ([`LIVE_RESULTS_v1.0.0.md`](docs/release/LIVE_RESULTS_v1.0.0.md), [`UAT_HELM_HA_v0.13.md`](docs/release/UAT_HELM_HA_v0.13.md)). It has not been run on a managed cluster (EKS, AKS, GKE).
- **Existing CAs:** Vault PKI and EJBCA ran live; AWS Private CA ran on an emulator; Sectigo, GlobalSign, Entrust, DigiCert and Google CAS were tested against recorded API responses ([`RELEASE_NOTES_v1.1.0.md`](docs/release/RELEASE_NOTES_v1.1.0.md), [`LIVE_RESULTS_UPSTREAM_CAS_v1.1.md`](docs/release/LIVE_RESULTS_UPSTREAM_CAS_v1.1.md)).
- **Post-quantum:** ML-DSA issuance interoperates with OpenSSL 3.5, and PQC waves installed on nginx and HAProxy over SSH and on a Kubernetes TLS Secret, with rollback shown on nginx and HAProxy ([`LIVE_RESULTS_PQC_v0.19.md`](docs/release/LIVE_RESULTS_PQC_v0.19.md), [`LIVE_RESULTS_PQC_W40_v1.1.md`](docs/release/LIVE_RESULTS_PQC_W40_v1.1.md)). Apache httpd 2.4 on OpenSSL 3.5 took an ML-DSA-65 wave, and both Apache and a Kubernetes Secret rolled back after a forced verify failure ([`LIVE_RESULTS_PQC_APACHE_K8S_ROLLBACK_v1.1.md`](docs/release/LIVE_RESULTS_PQC_APACHE_K8S_ROLLBACK_v1.1.md)).
- **Full regression on 1.1.0:** the 1.0.0 lab sweep was re-run on the v1.1.0 commit; smoke 446 of 446, no product regressions, with the failures and their causes listed ([`LIVE_RESULTS_v1.1.0_REGRESSION.md`](docs/release/LIVE_RESULTS_v1.1.0_REGRESSION.md)).
- **CT log monitoring:** a live run against crt.sh and Cert Spotter found the domain's certificates from another CA, notified once per finding and stayed silent on a re-scan ([`LIVE_RESULTS_CT_v1.1.md`](docs/release/LIVE_RESULTS_CT_v1.1.md)).
- **Trust-store push:** a real hub pushed and then removed a root on real agents in Debian 12 and Rocky 9, with two-person approval enforced (49 of 49 steps on Postgres and on SQLite; [`LIVE_RESULTS_TRUST_STORE_E2E_v1.1.md`](docs/release/LIVE_RESULTS_TRUST_STORE_E2E_v1.1.md)). Windows and macOS hosts have not been run.
- **Appliances and vendor services:** F5, Citrix, Intune, ServiceNow, Jira, Slack, PagerDuty and the cloud DNS and delivery plugins ran against mocks or stand-ins only. The list, and what each one needs, is in [`docs/ROADMAP.md`](docs/ROADMAP.md#proven-against-real-systems).

The proof pack (FIPS statement, control mapping, competitive matrix, draft pen-test scope) is in [`docs/release/proof-pack/`](docs/release/proof-pack/README.md). It dates from v0.21 and is due a 1.1 refresh. It has no customer references yet.

---

## Quick Start

**Prerequisites:** Docker + Docker Compose, or Go 1.27+ for local development.

```bash
git clone https://github.com/bpmforge/kryptkeeper.git
cd kryptkeeper
cp env.example .env
# Edit .env: set APP_BOOTSTRAP_TOKEN and KRYPTKEEPER_KEYSTORE_PASSPHRASE
# (compose refuses to start without either; they must be different values).
# Generate each with: openssl rand -hex 32
# env.example already sets KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true so the first
# boot creates the hub's default root CA. Remove that line to start with zero
# CAs and create the first root in the UI onboarding wizard instead.
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
issue its own TLS listener certificate. Two ways to get the first root:
leave `KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true` (a hub-held root, created
automatically), or unset it and the hub starts in first-run mode with zero CAs
(logs `[FIRST-RUN]`, `/readyz` is OK) so the UI onboarding wizard can create the
root. In first-run mode the listener serves an ephemeral self-signed certificate (no CA to
self-issue from), ACME/EST/CMP/WSTEP answer 503 `no CA configured yet; create a
root CA`, and SCEP/XCEP need a restart after the root exists. Set
`KRYPTKEEPER_CA_NAME` in `.env` before the first start to rename the bootstrap
root.

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

All configuration is via environment variables. See `env.example` for the full list and [docs/reference/ENVIRONMENT.md](docs/reference/ENVIRONMENT.md) for the variable table.

Note: `APP_BIND_ADDR` is a host only (default `127.0.0.1`) and `PORT` is the
port (default `8080`); they are joined to form the listen address.

---

## Architecture

```
┌───────────────────────────────────────────────────────┐
│  Kryptkeeper                                          │
│                                                       │
│  ┌──────────┐  ┌──────────┐  ┌───────────────────┐    │
│  │ Dashboard│  │   REST   │  │  Protocol Servers │    │
│  │(React/TS)│  │   API    │  │  ACME OCSP CRL    │    │
│  │  :3000   │  │  :8080   │  │  EST SCEP XCEP    │    │
│  └──────────┘  └────┬─────┘  └───────────────────┘    │
│                     │                                 │
│  ┌──────────────────▼──────────────────────────────┐  │
│  │                    CA Engine                    │  │
│  │  Root CA → Issuing CA → Certificate             │  │
│  │  Templates · Revocation · OCSP/CRL              │  │
│  └────────────────────┬────────────────────────────┘  │
│                       │                               │
│  ┌────────────────────▼────────────────────────────┐  │
│  │                  Storage Layer                  │  │
│  │  PostgreSQL · SQLite · PKCS#8 · PKCS#11         │  │
│  │  AWS KMS · GCP KMS · Azure Key Vault            │  │
│  │  (cloud KMS: emulator-tested)                   │  │
│  └─────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────┘
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

## Use your existing CA

Kryptkeeper can issue through the CA you already run or buy from: HashiCorp Vault PKI,
EJBCA, AWS Private CA, Google Cloud CAS, Sectigo, GlobalSign, Entrust, DigiCert or any
ACME CA. Add it under **Issuers**, create an external CA, and every front door above
(ACME, EST, SCEP, CMP, Windows autoenrollment, the API, cert-manager, Terraform) issues
through it, with Kryptkeeper's template policy applied first and every returned
certificate checked against the request. Revoking a certificate revokes it at that CA.
See [docs/ops/UPSTREAM_CAS.md](docs/ops/UPSTREAM_CAS.md).

## API Reference

The full OpenAPI 3.1 spec is at [`docs/openapi.yaml`](docs/openapi.yaml).

**Base URL:** `https://localhost:8080/api/v1` (TLS by default; `http://` only
when `KRYPTKEEPER_TLS_DISABLE=true`)

**Authentication:** Pass `Authorization: Bearer <token>` on every request (except `/meta` and `/auth/login`). Tokens can be:
- Bootstrap token (the `APP_BOOTSTRAP_TOKEN` you configured; not auto-generated or logged)
- JWT (HS256, when `AUTH_MODE=jwt`)
- OIDC token (RS256, when `AUTH_MODE=oidc`)
- API key (`kk_<kid>_<secret>`, created via `POST /api/v1/api-keys`)

**Core endpoints:** see [docs/reference/ENDPOINTS.md](docs/reference/ENDPOINTS.md); the full list is in the OpenAPI spec above.

---

## Key Storage

| Layer | Provider | Status |
|-------|----------|--------|
| 1 | Encrypted PKCS#8 PEM (Argon2id KDF) | Default; used by every test harness |
| 2 | PKCS#11 HSM via ThalesGroup/crypto11 | Tested on SoftHSM2; no vendor HSM tested |
| 3 | AWS KMS, Azure Key Vault | Validated against emulators only (moto, Lowkey Vault); not tried against real cloud accounts |
| 4 | HashiCorp Vault transit | Tested against a Vault dev server |
| 4 | GCP Cloud KMS | Tested against an in-repo emulator only; not tried against a real account |

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

**Environment:** Go 1.27+ (go.mod), Node 24 (`ui/.nvmrc`), PostgreSQL 16 or SQLite. Postgres support is backed by round-trip tests for every database-backed store (gated on `KRYPTKEEPER_TEST_POSTGRES_DSN`; CI runs them with `-p 1`).

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
instead of passing values inline. The chart installs and fails over on kind. It has not been run on EKS, AKS or GKE. A signed copy is published at
`oci://ghcr.io/bpmforge/charts/kryptkeeper`.

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

**FIPS posture.** Kryptkeeper uses the Go FIPS 140-3 module (CMVP status: see [docs/release/CMVP_STATUS.md](docs/release/CMVP_STATUS.md)). It is not itself a validated product. The FIPS image variant and the algorithm boundary are described in [docs/design/FIPS_POSTURE.md](docs/design/FIPS_POSTURE.md).

Report security issues to the project maintainers privately before public disclosure.

---

## Roadmap

What Kryptkeeper does not do yet is in [docs/ROADMAP.md](docs/ROADMAP.md). What shipped is in [CHANGELOG.md](CHANGELOG.md).

---

## Multi-tenancy

Multi-tenancy (`MULTI_TENANCY=on`) enforces tenant isolation as of v0.10: every API route is
checked by the tenant IDOR suite (`bash scripts/test/run.sh --suite tenant-idor`, 0 cross-tenant
leaks on SQLite and PostgreSQL). Instance-wide settings stay platform super-admin only while it
is on. The v0.9 start-up acknowledgement is no longer required;
`KRYPTKEEPER_MULTI_TENANCY_GATE=enforce` restores it as a rollback. Enforced boundary and
remaining limits: [docs/design/TENANCY_POSTURE.md](docs/design/TENANCY_POSTURE.md).

---

## License

Apache 2.0 — see [LICENSE](LICENSE). Licensing, dependency-licence policy and support: [docs/LICENSING_AND_SUPPORT.md](docs/LICENSING_AND_SUPPORT.md).

The core CA engine, all protocol servers, certificate discovery, and the management dashboard are free and open-source under Apache 2.0.
