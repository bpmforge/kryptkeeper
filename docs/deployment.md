# Deployment Guide

Three deployment targets: Docker Compose (dev/small teams), Kubernetes/Helm (production),
and bare metal (air-gapped / regulated environments).

## CGO Note

As of the switch to `modernc.org/sqlite` (pure Go), the Hub binary no longer
requires CGO for the SQLite backend — every binary in this repo, including
`kryptkeeper`, builds with `CGO_ENABLED=0` (this is what `.goreleaser.yaml`
and every Dockerfile here do). PostgreSQL (`KRYPTKEEPER_DB_MODE=postgres`,
`jackc/pgx`) remains available and is still the right choice for
multi-instance deployments regardless of CGO.

The **agent binary** (`kryptkeeper-agent`), the **cert-manager issuer**, and
the **Terraform provider** are also fully CGO-free.

---

## Docker Compose (quickstart / small teams)

### Prerequisites

- Docker 24+ and Docker Compose v2
- 512 MB RAM, 1 CPU minimum

### Steps

```bash
git clone https://github.com/bpmforge/kryptkeeper.git
cd kryptkeeper

# Build the UI (note: npm ci pulls from the public npm registry — this path is not air-gapped)
cd ui && npm ci && npm run build && cd ..

# Set a random bootstrap token
export APP_BOOTSTRAP_TOKEN=$(openssl rand -hex 20)
echo "Token: $APP_BOOTSTRAP_TOKEN"

# Start all services (Hub on SQLite + nginx dashboard; PostgreSQL is opt-in, see below)
docker compose up -d

# W19-23: the hub serves TLS by default (self-issued from its own CA), so
# /healthz needs that CA to verify -- export it once from the shared
# "tls-trust" volume (public certificate only, no key material):
docker run --rm -v kryptkeeper_tls-trust:/trust:ro alpine cat /trust/ca.pem > ca.pem
curl --cacert ca.pem https://localhost:8080/healthz
# → {"status":"ok"}
```

The dashboard is at http://localhost:3000 (plain HTTP to the browser --
dashboard's nginx is the one that speaks verified TLS to the hub; see "TLS
termination" below). Log in with token `$APP_BOOTSTRAP_TOKEN`.

### Running a tagged release instead of building from source (W20-02)

`docker-compose.yml`'s default `build:` block compiles the hub image from
your checkout, matching what `git clone` + `docker compose up` gives you
above. To run a signed, versioned release instead of a local build, override
the `image:` and drop the `build:` block via
`docker-compose.override.yml`:

```yaml
# docker-compose.override.yml
services:
  kryptkeeper:
    build: !reset null
    image: ghcr.io/bpmforge/kryptkeeper:0.9.0   # pin an exact tag (no "v" prefix), not :latest, for a reproducible pull
```

Before pulling, verify the tag the same way `.github/workflows/release.yml`
signed it -- see "Install from a signed release" under Bare Metal below for
the exact `cosign verify` invocation and expected identity; the same
identity/issuer pair applies to every `ghcr.io/bpmforge/*` image this
project publishes, not only the hub. Building from source (the default
above) remains the right choice while developing against an unreleased
change; pulling a tag is for running something that was actually released
and can be verified.

### Environment variables

Copy `.env.example` to `.env` and set at minimum:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `APP_BOOTSTRAP_TOKEN` | **Yes** | — | Initial admin token |
| `POSTGRES_PASSWORD` | No | `changeme` | PostgreSQL password; only used with the opt-in `postgres` profile |
| `KRYPTKEEPER_DB_MODE` | No | `sqlite` | `sqlite` or `postgres` |
| `KRYPTKEEPER_BASE_URL` | No | — | Public URL (for SCEP admin URL generation) |

### Notification provider

`APP_NOTIFICATION_PROVIDER` selects what happens to alerts:

- **`delivery`** (the Compose default): sends through SMTP, Slack, PagerDuty
  and webhook channels, and stores alert rules in the notification database.
  Use this for production.
- **`db`**: records deliveries in the database but does **not** send anything.
- **`file`** (the code default when the variable is unset): a development stub.

`db` and `file` never deliver, so the renewal scheduler does not treat an alert
as sent under them: notification-rule alerts and owner reminders are skipped
with no cooldown written, each is audited as `renewal_notification_sent` with
outcome `skipped` and the reason (at most once per certificate and rule per 24 hours),
and the hub logs a WARNING at startup when rules exist.
`POST /api/v1/notifications/test-delivery` answers `dispatched=false` with a
note. `KRYPTKEEPER_RENEWAL_RULE_SEND_CAP` (default 500) bounds how many rule
alerts one scan sends; the remainder roll to the next scan.

A bare-metal or Helm install that leaves it unset gets `file`; set `delivery`
to get alerts. The rule endpoints return 503 if the notification store cannot
be opened.

### Missing CA keys at startup

The hub refuses to start when an active CA has no usable key in the keystore,
which usually means `KRYPTKEEPER_KEYSTORE_DIR` or `KRYPTKEEPER_DATA_DIR`
changed, the keystore volume is not mounted, or the passphrase is wrong. Fix
the cause. For a deliberate recovery only, set
`KRYPTKEEPER_ALLOW_MISSING_CA_KEYS=true`: those CAs cannot issue or sign
CRL/OCSP until their keys are restored. Remove the setting afterwards.

### Audit trail storage

`APP_AUDIT_PROVIDER` selects where the audit trail is kept:

- **Unset (default):** the database-backed trail (`audit_log`, append-only
  triggers) whenever the hub has a core database, which is every
  `APP_CERTIFICATE_PROVIDER=ca` deployment (SQLite or PostgreSQL). Without a
  core database it falls back to the file store. The startup log names the
  choice (`audit provider: db (default)`).
- **`db`** or **`file`:** forces that store. `file` writes append-only JSON
  Lines to `APP_AUDIT_FILE` (default `./var/bootstrap-audit.json`); the path
  needs to be on a persistent volume. A file written by an earlier release (a
  single JSON array) is converted on first start and the original is kept as
  `<file>.bak`.

The hub refuses to start if the chosen audit store cannot be opened. The DB
store writes to the core database: with `APP_AUDIT_DB_DSN` unset it resolves
its DSN exactly as the core DB does (`APP_CORE_DB_DSN`, then
`KRYPTKEEPER_DB_DSN`, then `DATABASE_URL` for PostgreSQL; `APP_CORE_DB_DSN`,
then `KRYPTKEEPER_DATA_DIR/kryptkeeper.db` for SQLite), with the same driver
(`KRYPTKEEPER_DB_MODE`). A PostgreSQL hub never audits into a local SQLite
file; with no DSN it fails to start. Set `APP_AUDIT_DB_DSN` only to put the
audit trail in a different database.

### SQLite vs PostgreSQL

SQLite is the default and requires no extra service. Switch to PostgreSQL for
multi-instance deployments. The `postgres` service in
`docker-compose.override.yml` is inert unless its profile is enabled
(`docker compose --profile postgres up -d`, or `COMPOSE_PROFILES=postgres` in
`.env`). To point the hub at it, also set in `.env`:

```bash
KRYPTKEEPER_DB_MODE=postgres
DATABASE_URL=postgres://kryptkeeper:${POSTGRES_PASSWORD}@postgres:5432/kryptkeeper?sslmode=disable
```

### Memory sizing

Measured RSS on `main` at `26e17cac`, SQLite CA provider
(docs/perf/rc3/README.md and 03-measurements.md): 172 MB idle at 10.5k
certificates; 629 to 665 MB idle at 55k to 61k; about 1.0 GB (964 to 1,066 MB)
after calling the four report endpoints (Go keeps the freed pages, so this is
retained); 970 MB peak during an 8-way issue burst. Idle RSS grows by about
11 KB per certificate. A 30-way bad-login spray added about 325 MB (664 to 989 MB)
that RSS kept afterwards (a high-water mark: login hashing concurrency is capped, but the Go
runtime retains the freed buffers, so this is not unbounded growth). Plan for a 512Mi request and a 2Gi limit, and
set `GOMEMLIMIT` to about 80% of the limit so the Go GC tightens before the
kernel OOM-kills the hub:

| Where | Request | Limit | `GOMEMLIMIT` |
|-------|---------|-------|--------------|
| Helm (`resources`, `config.goMemLimit`) | 512Mi | 2Gi | `1600MiB` |
| Compose (`KRYPTKEEPER_MEM_LIMIT`, `GOMEMLIMIT`) | n/a | 2g | `1600MiB` |

Change the limit and `GOMEMLIMIT` together. Extrapolating the 11 KB per
certificate, the 2Gi limit is reached somewhere above 100k certificates (an
extrapolation: nothing above 61k was measured, and Postgres at scale was not).
Report calls add a transient of 300 to 380 MB on top of idle, so size for idle
plus that. Larger inventories need a larger limit.

### Client IP behind a reverse proxy

IP-keyed limits (login, refresh, SSO, ACME/OCSP/CRL/EST/SCEP/CMP) bucket by
the TCP peer unless the peer is listed in `APP_TRUSTED_PROXY_CIDRS`. Behind a
proxy with the variable unset, every user shares one bucket and about 9 failed
logins per minute locks everyone out.

- **Compose:** `docker-compose.yml` pins the network to `172.29.231.0/24`, gives
  the dashboard's nginx the fixed address `172.29.231.10`, and sets
  `APP_TRUSTED_PROXY_CIDRS=172.29.231.10/32`. Only that one address is
  trusted, not the subnet, so connections to the published `:8080` (which come
  from the bridge gateway) cannot choose their own bucket. `nginx.conf` appends
  to `X-Forwarded-For` with `$proxy_add_x_forwarded_for`. If the range clashes
  with your network, change the subnet and the address together.
- **Helm:** `config.trustedProxyCIDRs` defaults to empty because the ingress
  controller's pod CIDR is cluster specific. Set it to the narrowest range
  containing only your ingress controller pods. `helm install` prints a warning
  when `ingress.enabled=true` and it is empty.

### TLS termination

Two options as of W19-14; pick one, not both on the same port.

**Docker Compose default (W19-23):** `docker-compose.yml` runs the hub with
TLS on out of the box -- `KRYPTKEEPER_TLS_SELF_ISSUE` is intentionally left
unset (resolveTLSMode self-issues automatically whenever a CA engine exists
and TLS isn't otherwise disabled), `KRYPTKEEPER_TLS_SANS` includes
`kryptkeeper` (the name the dashboard's nginx and any other compose peer
dial), and `KRYPTKEEPER_BASE_URL` defaults to `https://localhost:8080` for
ACME/EST/SCEP/CMP clients running on the host. The hub writes its listener
cert, key, and the issuing CA's chain (`ca.pem`, no key material) under
`KRYPTKEEPER_DATA_DIR/tls/`, and a second copy of just `ca.pem` into
`KRYPTKEEPER_TLS_TRUST_EXPORT_DIR` (`/var/kryptkeeper/tls-trust`), which
lands in the compose-only `tls-trust` volume -- a dedicated, key-free volume
shared read-only with the `dashboard` and referenced by the hub's own
`/healthcheck` binary via `HEALTHCHECK_CA_FILE`. `appdata` (which also holds
the keystore and `tls.key`) is never shared with another container --
CLAUDE.md: private key material never leaves its boundary.

- **Export the CA to curl/verify against the hub from the host:**
  `docker run --rm -v kryptkeeper_tls-trust:/trust:ro alpine cat /trust/ca.pem > ca.pem`,
  then `curl --cacert ca.pem https://localhost:8080/readyz`.
- **Dashboard's nginx** (`nginx.conf`) proxies `/api`, `/healthz`, `/readyz`
  to `https://kryptkeeper:8080` with `proxy_ssl_trusted_certificate` pointed
  at the mounted `ca.pem`, `proxy_ssl_verify on`, and `proxy_ssl_name
  kryptkeeper` -- a wrong or missing CA fails the proxy, it never silently
  falls back to trusting an unverified cert. The dashboard container's
  entrypoint waits (bounded retry, not condition: service_healthy -- Podman
  5.x/6.x's OCI healthcheck status is independently flaky for this image)
  for that CA file to actually exist before starting nginx, so a
  slow-to-boot hub cannot race the dashboard into serving over an unverified
  connection.
- **Opting out to plain HTTP:** set `KRYPTKEEPER_TLS_DISABLE=true` in `.env`.
  You must also override `HEALTHCHECK_URL=http://127.0.0.1:8080/healthz`
  (compose's default assumes TLS is on) and hand-edit `nginx.conf`'s
  `proxy_pass` lines back to `http://kryptkeeper:8080` (dropping the
  `proxy_ssl_*` directives) -- this is a deliberate manual step, not a
  toggle, so opting a PKI product's own stack into cleartext is never the
  path of least resistance.

**Reverse proxy** (nginx, Caddy, Cloudflare Tunnel) in front of plain HTTP on
port 8080 -- set `KRYPTKEEPER_TLS_DISABLE=true` on the hub so it doesn't also
try to serve TLS on that port. Example Caddyfile:

```
kryptkeeper.example.com {
    reverse_proxy localhost:8080
}
```

**The hub serves TLS itself** -- required for EST (RFC 7030 mandates TLS)
and recommended for every other protocol endpoint, since this is a PKI
product and a PKI product should not hand out or accept certificates over
cleartext:

- `KRYPTKEEPER_TLS_CERT_FILE` / `KRYPTKEEPER_TLS_KEY_FILE`: an
  operator-supplied cert/key pair (e.g. from the reverse-proxy's ACME
  account, or a cert this same hub issued for itself via its API).
- `KRYPTKEEPER_TLS_SELF_ISSUE=true`: the hub issues and persists its own
  listener certificate from its default CA at startup (90-day validity,
  reused across restarts until 30 days before expiry, then re-issued).
  Requires `APP_CERTIFICATE_PROVIDER=ca`. `KRYPTKEEPER_TLS_SANS` (CSV)
  controls the SAN list; defaults to `localhost,127.0.0.1` plus the host of
  `KRYPTKEEPER_BASE_URL`.
- Absent either of those and `KRYPTKEEPER_TLS_DISABLE=true`, the hub
  self-issues when it has a CA to issue from, else falls back to plain HTTP
  with a startup warning rather than refusing to start.

`KRYPTKEEPER_BASE_URL`'s scheme must agree with whichever mode is active --
startup fails with a clear error otherwise (protocol clients built from a
mismatched URL would be told to dial the wrong scheme).

---

## Kubernetes / Helm (production)

### Prerequisites

- Kubernetes 1.26+
- Helm 3.12+
- cert-manager (optional, for automatic TLS)
- A PostgreSQL instance you manage (this chart does not bundle a PostgreSQL sub-chart — set
  `secrets.databaseURL` or `secrets.existingSecret` to point at one you run separately; SQLite also
  works for single-replica installs via `config.dbMode=sqlite`)

### Add the Helm repository

```bash
helm repo add kryptkeeper https://kryptkeeper.github.io/helm-charts
helm repo update
```

Or install directly from a checked-out copy of this repo: `helm install kryptkeeper ./charts/kryptkeeper ...`.

### Minimal install (SQLite, no TLS)

```bash
helm install kryptkeeper kryptkeeper/kryptkeeper \
  --namespace kryptkeeper \
  --create-namespace \
  --set config.dbMode=sqlite \
  --set secrets.bootstrapToken="$(openssl rand -hex 20)" \
  --set secrets.keystorePassphrase="$(openssl rand -hex 32)"
```

### Production install (PostgreSQL + TLS)

Values keys below are the chart's real schema (`values.yaml`) — `helm show values ./charts/kryptkeeper`
is the source of truth if this drifts again. Create `values-prod.yaml`:

```yaml
replicaCount: 1   # keep at 1 until W6-01 (process-local schedulers) ships — see values.yaml's pdb comment

config:
  authMode: bootstrap
  dbMode: postgres

# Dev-style inline secrets — see the "Secrets" section below for
# existingSecret / External Secrets Operator alternatives that avoid putting
# credentials in a values file at all.
secrets:
  bootstrapToken: ""     # set via --set or a separate values file, not committed
  keystorePassphrase: ""
  databaseURL: ""        # postgres://user:pass@host:5432/kryptkeeper?sslmode=require

ingress:
  enabled: true
  className: nginx
  hosts:
    - host: kryptkeeper.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: kryptkeeper-tls
      hosts: [kryptkeeper.example.com]
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod

persistence:
  storageClass: standard
  size: 10Gi
```

Install:

```bash
helm install kryptkeeper kryptkeeper/kryptkeeper \
  --namespace kryptkeeper \
  --create-namespace \
  --values values-prod.yaml
```

### Secrets: existingSecret and External Secrets Operator

Putting real credentials in a `values-prod.yaml` (even ungitted) is a dev-only pattern. For anything
beyond a quickstart, set `secrets.existingSecret` to the name of a Secret you manage yourself instead of
the `secrets.bootstrapToken`/`keystorePassphrase`/`databaseURL` inline fields — the chart then skips
rendering its own Secret entirely and references yours:

```bash
kubectl create secret generic kryptkeeper-credentials \
  --namespace kryptkeeper \
  --from-literal=APP_BOOTSTRAP_TOKEN="$(openssl rand -hex 20)" \
  --from-literal=KRYPTKEEPER_KEYSTORE_PASSPHRASE="$(openssl rand -hex 32)" \
  --from-literal=DATABASE_URL="postgres://kk:password@postgres:5432/kryptkeeper?sslmode=require"

helm install kryptkeeper kryptkeeper/kryptkeeper \
  --namespace kryptkeeper \
  --set secrets.existingSecret=kryptkeeper-credentials
```

If you run [External Secrets Operator](https://external-secrets.io), the chart can render an
`ExternalSecret` that syncs into that same Secret name from Vault/AWS/GCP/Azure secret managers — set
`externalSecrets.enabled=true`, `externalSecrets.secretStoreRef.name`, and `externalSecrets.data` (see
`values.yaml` for the exact shape). This requires the ESO CRDs and a `SecretStore`/`ClusterSecretStore`
already configured in-cluster — this chart does not create either.

### HA / observability objects (all opt-in)

- `pdb.enabled=true` — renders a `PodDisruptionBudget` (`pdb.minAvailable`, default `1`).
- `networkPolicy.enabled=true` — renders a `NetworkPolicy` restricting inbound traffic to the app port;
  outbound (Postgres, SMTP, cloud KMS/notification APIs, agent connections) is left unrestricted. Scope
  ingress with `networkPolicy.allowedIngressNamespaceSelector` (e.g. your ingress controller's namespace).
- `metrics.serviceMonitor.enabled=true` — renders a Prometheus Operator `ServiceMonitor` scraping
  `/metrics` (real since W1-05). Requires the Prometheus Operator CRDs in-cluster.

### cert-manager issuer (K8s-native certificate issuance)

```bash
helm install kryptkeeper-issuer kryptkeeper/kryptkeeper-certmanager-issuer \
  --namespace kryptkeeper \
  --set hub.url=https://kryptkeeper.example.com \
  --set hub.tokenSecretRef.name=kryptkeeper-bootstrap \
  --set defaults.caID=<ca-id> \
  --set defaults.templateID=<template-id>
```

Once installed, annotate a `Certificate` resource with:

```yaml
spec:
  issuerRef:
    name: kryptkeeper
    kind: KryptKeeperIssuer
    group: certmanager.kryptkeeper.io
```

---

## Bare Metal (air-gapped / regulated)

### Prerequisites

- Linux x86_64 or arm64 (Ubuntu 22.04+ / RHEL 9+ / Debian 12+)
- Go 1.22+ (only if building from source)
- SQLite3 or PostgreSQL

### For air-gapped environments

**For regulated or air-gapped deployments**, see [Air-Gap / Offline Install](ops/AIRGAP_INSTALL.md)
for the complete offline procedure, including how to bundle and mirror container images and the
Helm chart across an air gap.

Note: The Docker Compose deployment path is not air-gap-capable as written — its `ui-build`
service runs `npm ci` against the public npm registry on each deployment. For air-gapped installs,
use the Kubernetes/Helm path with the offline bundle procedure.

### Install from a signed release (W20-02)

Every `v*` tag runs `.github/workflows/release.yml`, which builds hub/agent/
certmanager/mcp binaries (linux amd64+arm64, darwin arm64) via goreleaser
(`.goreleaser.yaml`), packages them as `.tar.gz` archives plus hub `.deb`/`.rpm`
(nfpm), and generates a `checksums.txt` and a CycloneDX SBOM per archive. It
signs two things, both **keyless** with cosign (Sigstore, the workflow's GitHub
OIDC identity -- no key to fetch or protect): `checksums.txt` (producing
`checksums.txt.sig` and `checksums.txt.pem`) and the image manifests pushed to
`ghcr.io/bpmforge/*`. Archives, packages and SBOMs are not signed one by one;
they are covered by the checksums. Image tags carry no `v` prefix (goreleaser's
`{{ .Version }}`): `0.9.0`, `0.9` and `latest`.

```bash
VERSION=0.9.0          # the tag is v0.9.0; file names and image tags drop the "v"
ARCH=linux_amd64       # or linux_arm64, darwin_arm64
BASE="https://github.com/bpmforge/kryptkeeper/releases/download/v${VERSION}"

curl -fsSLO "${BASE}/kryptkeeper_${VERSION}_${ARCH}.tar.gz"
curl -fsSLO "${BASE}/checksums.txt"
curl -fsSLO "${BASE}/checksums.txt.sig"
curl -fsSLO "${BASE}/checksums.txt.pem"

# 1. Verify the signature on checksums.txt. The identity pattern pins the
#    release workflow of this repository, so a signature from a fork or a
#    different workflow is rejected, not just "a" valid Sigstore signature.
cosign verify-blob \
  --certificate-identity-regexp '^https://github\.com/bpmforge/kryptkeeper/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --signature checksums.txt.sig \
  --certificate checksums.txt.pem \
  checksums.txt

# 2. Verify the archive against the (now trusted) checksums.
sha256sum --ignore-missing -c checksums.txt

tar xzf "kryptkeeper_${VERSION}_${ARCH}.tar.gz"
install -m 0755 kryptkeeper /usr/local/bin/kryptkeeper
kryptkeeper --version   # confirms the binary reports the same tag (also on GET /api/v1/meta once running)
```

The `.deb`/`.rpm` packages and the `kryptkeeper-agent`/`kryptkeeper-certmanager`/
`kryptkeeper-mcp` archives are listed in the same `checksums.txt`, so step 1
covers them too; download the file and run step 2 for each.

Container images are verified against the signed manifest:

```bash
cosign verify \
  --certificate-identity-regexp '^https://github\.com/bpmforge/kryptkeeper/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/bpmforge/kryptkeeper:${VERSION}
```

Swap `kryptkeeper` for `kryptkeeper-agent`, `kryptkeeper-certmanager`, or
`kryptkeeper-mcp` for the other three images; each is published multi-arch
under `ghcr.io/bpmforge/*`, tagged `X.Y.Z`, `X.Y`, and `latest`. To pin to one
release, replace the regexp flag with `--certificate-identity
"https://github.com/bpmforge/kryptkeeper/.github/workflows/release.yml@refs/tags/v${VERSION}"`.

### Build from source (CGO required for SQLite)

For non-air-gapped bare metal deployments, you can build directly from source:

```bash
git clone https://github.com/bpmforge/kryptkeeper.git
cd kryptkeeper
go build -o /usr/local/bin/kryptkeeper ./cmd/kryptkeeper/

# Agent (CGO-free)
CGO_ENABLED=0 go build -o /usr/local/bin/kryptkeeper-agent ./cmd/kryptkeeper-agent/
```

### systemd unit (Hub)

```ini
# /etc/systemd/system/kryptkeeper.service
[Unit]
Description=Kryptkeeper PKI Hub
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
User=kryptkeeper
Group=kryptkeeper
ExecStart=/usr/local/bin/kryptkeeper
EnvironmentFile=/etc/kryptkeeper/env
Restart=on-failure
RestartSec=10s
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/kryptkeeper
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```bash
# /etc/kryptkeeper/env
AUTH_MODE=bootstrap
APP_BOOTSTRAP_TOKEN=<your-token>
APP_BIND_ADDR=0.0.0.0
PORT=8080
KRYPTKEEPER_DB_MODE=sqlite
KRYPTKEEPER_KEYSTORE_DIR=/var/lib/kryptkeeper/keys
KRYPTKEEPER_KEYSTORE_PASSPHRASE=<passphrase>
```

```bash
useradd -r -s /sbin/nologin kryptkeeper
mkdir -p /var/lib/kryptkeeper/keys
chown -R kryptkeeper:kryptkeeper /var/lib/kryptkeeper

systemctl daemon-reload
systemctl enable --now kryptkeeper
journalctl -u kryptkeeper -f
```

### Satellite agent systemd unit

```bash
kryptkeeper-agent --generate-systemd > /etc/systemd/system/kryptkeeper-agent.service
# Edit EnvironmentFile with your Hub URL, AGENT_ID, AGENT_TOKEN
systemctl enable --now kryptkeeper-agent
```

The agent derives its ACME directory URL from `KRYPTKEEPER_HUB_URL` alone
(`<KRYPTKEEPER_HUB_URL>/acme/directory`) — a renewal task pushed by the Hub
carries no separate CA/ACME URL field (W19-26 removed it as dead: the field
was always declared and stored, never assigned by the Hub or read by the
agent). There is nothing to configure here beyond the one Hub URL you already
set for registration/heartbeat/inventory.

### Trusting a hub-issued TLS certificate (W19-32)

The Hub self-issues its own TLS listener certificate by default
(`APP_CERTIFICATE_PROVIDER=ca`), so an agent talking to it over HTTPS needs
an explicit trust anchor unless the Hub sits behind a publicly-trusted
certificate instead. Set one of:

```bash
KRYPTKEEPER_HUB_CA_CERT=       # inline PEM CA bundle
KRYPTKEEPER_HUB_CA_CERT_FILE=  # path to the same
```

This pool is used for every connection the agent makes to the Hub —
registration, heartbeat, inventory push, task poll, result submit, and the
ACME renewer's directory/order/challenge calls (`internal/agentclient`) — all
pinned to TLS 1.2 minimum. Leaving both unset falls back to the system root
store, unchanged from pre-W19-32 behaviour. A bundle that fails to parse is a
startup error (`log.Fatalf`), not a silent fallback to system roots, mirroring
`KRYPTKEEPER_WINRM_CA_CERT`/`_FILE` and `KRYPTKEEPER_K8S_CA_CERT`/`_FILE`
elsewhere in the product.

There is deliberately **no** insecure-skip-verify option for this: an agent
that can be told to skip verification can be pointed at a fake hub and made
to leak its enrollment token and discovered certificate inventory to it.

The ACME HTTP-01 challenge itself is validated by the Hub dialing the agent
back on plain HTTP port 80 per RFC 8555 — that leg is unaffected by any of
this, since it carries no TLS handshake to verify.

### PKCS#11 / HSM (regulated environments)

Build with HSM support:

```bash
go build -tags pkcs11 -o /usr/local/bin/kryptkeeper ./cmd/kryptkeeper/
```

Required environment variables:

```bash
KRYPTKEEPER_KEY_BACKEND=pkcs11
KRYPTKEEPER_PKCS11_LIB=/usr/lib/softhsm/libsofthsm2.so
KRYPTKEEPER_PKCS11_TOKEN_LABEL=kryptkeeper
KRYPTKEEPER_PKCS11_PIN=<pin>
```

### Firewall rules

| Port | Protocol | Direction | Purpose |
|------|----------|-----------|---------|
| 8080 | TCP | Inbound | Hub API + Dashboard |
| 5432 | TCP | Outbound | PostgreSQL (if external) |
| 443 | TCP | Outbound | Agent → Hub (if TLS) |

The agent only makes outbound connections — no inbound ports required on agent hosts.
