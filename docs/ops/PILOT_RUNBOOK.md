# Private design-partner pilot runbook

Audience: **one operator**, running Kryptkeeper on a single host from a
**source tarball / clone + Docker Compose + SQLite**. That is the supported
pilot shape. Helm/GHCR is a different deployment story and is **not** the
pilot path — see `PILOT_KNOWN_GAPS.md` before you consider it.

Read `PILOT_KNOWN_GAPS.md` first. It states what is verified, what is not,
and where the shipped docs disagree with the shipped code.

---

## 1. Prerequisites

- Docker Engine + Compose v2 (`docker compose version`).
- ~4 GB free disk, 2 vCPU. The stack compiles Go **and** runs `npm ci` on
  first `up`, so first boot is slow (typically 5–15 min) and needs **outbound
  internet** for `go mod download` and the npm registry.
- Free host ports **8080** (API) and **3000** (dashboard).
- `curl` and `jq` on the host for the day-one steps.
- `openssl` — certificate issuance takes a **CSR you generate**. Kryptkeeper
  does not generate subject private keys for you; the key never leaves the
  host that owns it.
- The source tree (tarball or `git clone`). Compose **builds from this
  context** (`build.context: .`) by default in this runbook. As of W20-02, a
  signed, versioned release image is also available (see "Installing from a
  signed release" after section 8) if you would rather pull a verified,
  tagged build than compile one — the pilot path documented here still
  defaults to source, since a pilot host frequently wants to run an
  unreleased fix.

## 2. Environment

```bash
cd kryptkeeper
cp env.example .env       # note: env.example, NOT .env.example
```

Edit `.env`. Two variables matter on day one:

| Variable | Why |
|---|---|
| `APP_BOOTSTRAP_TOKEN` | **Required.** Compose refuses to start without it (`${APP_BOOTSTRAP_TOKEN:?set APP_BOOTSTRAP_TOKEN}`). It is your admin bearer token in `AUTH_MODE=bootstrap`. It is **not** auto-generated and **not** printed to the logs for you to collect — you choose it. |
| `KRYPTKEEPER_KEYSTORE_PASSPHRASE` | **Set it explicitly.** Unset, Compose defaults it to `APP_BOOTSTRAP_TOKEN`. If you later rotate the bootstrap token without realising the keystore was encrypted under it, the CA keystore stops decrypting. Set both, independently, once, before first boot. |

Generate them, don't invent them:

```bash
printf 'APP_BOOTSTRAP_TOKEN=%s\n' "$(openssl rand -hex 32)" >> .env
printf 'KRYPTKEEPER_KEYSTORE_PASSPHRASE=%s\n' "$(openssl rand -hex 32)" >> .env
```

Keep both in a password manager. The keystore passphrase is not recoverable
from the volume, and without it the CA keys are ciphertext.

Defaults you get without touching anything else: `AUTH_MODE=bootstrap`,
`KRYPTKEEPER_DB_MODE=sqlite`, real crypto providers
(`APP_CERTIFICATE_PROVIDER=ca`, `APP_DISCOVERY_PROVIDER=scanner`,
`APP_NOTIFICATION_PROVIDER=delivery`), data and keys under the `appdata`
volume at `/var/kryptkeeper`.

**Postgres is not started by default and you do not need it for the pilot.**
`docker-compose.override.yml` defines a `postgres` service behind an inactive
profile; a plain `docker compose up` ignores it entirely.

**TLS (W19-14/W19-23).** This pilot's compose stack runs the hub over HTTPS
by default: absent any `KRYPTKEEPER_TLS_*` override, the hub self-issues its
own listener certificate from its own CA rather than silently serving
cleartext (this is a PKI product; see `docs/deployment.md`'s TLS section for
the full option set). Every in-stack consumer trusts it properly --
`/healthcheck` verifies against the CA (`HEALTHCHECK_CA_FILE`), and
`dashboard`'s nginx proxies to `https://kryptkeeper:8080` with
`proxy_ssl_verify on` -- so this is no longer the plain-HTTP-only pin W19-14
originally shipped.

To reach the hub directly from the host (curl, a script, an external ACME
client), export the CA once from the compose-only `tls-trust` volume -- it
holds only the CA certificate, never a key:

```bash
docker run --rm -v kryptkeeper_tls-trust:/trust:ro alpine cat /trust/ca.pem > ca.pem
curl --cacert ca.pem https://localhost:8080/readyz
```

To opt this pilot back out to plain HTTP: set `KRYPTKEEPER_TLS_DISABLE=true`
in `.env`, override `HEALTHCHECK_URL=http://127.0.0.1:8080/healthz`, and
hand-edit `nginx.conf` back to `proxy_pass http://kryptkeeper:8080` (drop the
`proxy_ssl_*` lines) -- or terminate TLS at a reverse proxy in front of
`dashboard`/`kryptkeeper` instead if you need a different HTTPS story for
the pilot's external URL.

## 3. Bring the stack up

```bash
docker compose up -d
docker compose ps
```

Three services: `kryptkeeper` (API), `ui-build` (one-shot, compiles the
dashboard into a volume, then exits — `Exited (0)` is success), `dashboard`
(nginx). `dashboard` deliberately waits for `kryptkeeper` to be *healthy* and
`ui-build` to have *completed*, so **port 3000 refuses connections until the
UI build finishes**. That is expected on first boot, not a fault.

Watch progress:

```bash
docker compose logs -f ui-build     # npm ci && npm run build
docker compose logs -f kryptkeeper
```

## 4. Verify

```bash
curl -fsS --cacert ca.pem https://localhost:8080/healthz          # liveness
curl -fsS --cacert ca.pem https://localhost:8080/readyz | jq .    # readiness (deps checked)
curl -fsS --cacert ca.pem https://localhost:8080/api/v1/meta | jq .

export KK_TOKEN='<APP_BOOTSTRAP_TOKEN from .env>'
curl -fsS --cacert ca.pem -H "Authorization: Bearer $KK_TOKEN" \
  https://localhost:8080/api/v1/cas | jq .
```

Then open the dashboard: **http://localhost:3000**. Sign in with the
bootstrap token.

If `/api/v1/cas` returns 401, the token in your shell and the token in `.env`
disagree — the container reads `.env` at `up` time, so re-run
`docker compose up -d` after editing it.

## 5. Day one: root CA → first certificate → discovery

### 5a. Create a root CA

```bash
curl -fsS --cacert ca.pem -X POST https://localhost:8080/api/v1/cas \
  -H "Authorization: Bearer $KK_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"Pilot Root","type":"root","algorithm":"ECDSA-P256","subject_cn":"Pilot Root CA"}' | jq .
```

`subject_cn` is the only required field (`docs/openapi.yaml` `POST /cas`).
Alternatively set `KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true` plus
`KRYPTKEEPER_CA_NAME` in `.env` and let first boot create it.

Record the returned CA id.

### 5b. Issue the first certificate

Issuance is **CSR-in**: you generate the key and CSR, Kryptkeeper signs it.

```bash
openssl req -newkey rsa:2048 -nodes \
  -keyout pilot.key -out pilot.csr -subj "/CN=app.pilot.example"

curl -fsS --cacert ca.pem -H "Authorization: Bearer $KK_TOKEN" \
  https://localhost:8080/api/v1/templates | jq '.data[] | {id, name}'

jq -Rs --arg ca "<ca-id>" --arg tpl "<template-id>" \
  '{ca_id:$ca, template_id:$tpl, csr_pem:.}' pilot.csr > issue.json

curl -fsS --cacert ca.pem -X POST https://localhost:8080/api/v1/certificates \
  -H "Authorization: Bearer $KK_TOKEN" -H 'Content-Type: application/json' \
  --data @issue.json | jq .
```

`201` = issued. `202` = the template carries an approval gate and the request
is queued — approve it under **Pending Actions** in the dashboard.

In the UI the same flow is the **Issue** wizard, which shows the exact
`openssl` command and takes the pasted CSR.

Keep `pilot.key` on the host that will serve it. Do not send it anywhere.

### 5c. First discovery scan

```bash
curl -fsS --cacert ca.pem -X POST https://localhost:8080/api/v1/discovery/scans \
  -H "Authorization: Bearer $KK_TOKEN" -H 'Content-Type: application/json' \
  -d '{"scan_type":"fast","target":"10.0.0.0/24"}' | jq .

curl -fsS --cacert ca.pem -H "Authorization: Bearer $KK_TOKEN" \
  https://localhost:8080/api/v1/discovery/scan-jobs | jq '.data[] | {id,status,type}'
```

`scan_type` is one of `full | targeted | fast | deep` (network — `target`
required, host or CIDR) or `cloud_acm | cloud_azure_kv | cloud_gcp_cm`
(connector-scoped, **no** `target`). Optional `ports` merges extra ports into
the scan type's list. Results land in the **Discovery** page: endpoints,
certificates, expiry, TLS/crypto posture, risk badges.

Scan only ranges you are authorised to scan. Start with one /24.

## 6. Daily operations

| What | Where |
|---|---|
| Estate at a glance, expiring soon, attention items | Dashboard → `GET /api/v1/dashboard/summary` |
| Expiry horizon over time | Expiry Timeline page |
| Open items needing a human | Pending Actions → `GET /api/v1/dashboard/actions`, `.../ack`, `.../resolve` |
| Alert routing | Notifications: `GET /api/v1/notifications/rules`, `/summary`, `/deliveries` |
| Prove a channel works before you rely on it | `POST /api/v1/notifications/test-delivery` |
| Mute a known-noisy source | `POST /api/v1/notifications/silences` |
| Everything that happened | Audit page → `GET /api/v1/audit` (append-only) |

Alert channels are env-configured in `.env`: `SMTP_HOST`/`SMTP_FROM`,
`SLACK_WEBHOOK_URL`, `PAGERDUTY_ROUTING_KEY`. Set at least one on day one and
send a test delivery — an unproven channel is not an alert.

Expiry/renewal cadence: `RENEWAL_POLL_HOURS` (default 6) and
`RENEWAL_THRESHOLD_DAYS` (default 30).

**Know what auto-renewal will and will not do.** The scheduled renewal sweep
*executes* a push only for targets that are `auto_renew`, `install_mode=ssh`,
carry a complete install profile (server type, cert path, key path) and a
credential reference. Every other target — Windows/IIS, F5, Citrix, k8s,
ACME — is **notify-only** on the sweep. See `PILOT_KNOWN_GAPS.md` §Facts.

## 7. Backup

**Read this before you have anything worth losing.** The scripted DR path
(`scripts/deploy/backup.sh`, `docs/ops/DR_RUNBOOK.md`,
`docs/ops/RESTORE_DRILL.md`) is **Postgres-shaped**: `backup.sh` hard-requires
`DATABASE_URL` and `pg_dump`. **A SQLite pilot has no scripted database
backup path.** Those two runbooks remain the reference for the restore
*ordering* rules, the keystore bundle semantics, and the executed drills —
but their DB half does not apply to you.

For the pilot, back up the whole `appdata` volume (database **and** keystore
live under `/var/kryptkeeper`), with the stack stopped so SQLite is quiescent:

```bash
docker volume ls | grep appdata          # real name is project-prefixed
docker compose stop
docker run --rm \
  -v <project>_appdata:/data:ro -v "$PWD/backups":/backup \
  alpine tar czf /backup/kk-appdata-$(date -u +%Y%m%d).tar.gz -C /data .
docker compose start
```

Restore is the same in reverse, into a **fresh** volume on a stack that is
down — never merge a backup into a running instance.

Recommended additionally, because it is the only backup that survives losing
the whole host's Docker state in a portable form:

```bash
curl -fsS --cacert ca.pem -X POST https://localhost:8080/api/v1/admin/backup \
  -H "Authorization: Bearer $KK_TOKEN" -H 'Content-Type: application/json' \
  -d '{"backup_passphrase":"<separate backup passphrase>"}' > keys-$(date -u +%Y%m%d).json
```

The backup passphrase is a **separate secret** from
`KRYPTKEEPER_KEYSTORE_PASSPHRASE`. Store it apart from the bundle: bundle +
passphrase together = every CA key. Non-extractable backends (PKCS#11, cloud
KMS, Vault) are recorded as skipped by design — not applicable to a default
pilot, which uses the software backend.

Cadence for a 2–3 week pilot: nightly volume snapshot, kept off-host, plus a
key bundle after any CA change. **Test one restore inside the first week.** A
backup you have never restored is a hypothesis.

## 8. When something breaks

Collect, in this order:

```bash
docker compose ps
docker compose logs --since 1h kryptkeeper > kk-api.log
docker compose logs ui-build > kk-uibuild.log
curl -sS --cacert ca.pem https://localhost:8080/readyz | jq .
curl -sS --cacert ca.pem https://localhost:8080/api/v1/meta | jq .   # version + commit
```

Common first-hour cases:

- **`docker compose up` exits immediately** — `APP_BOOTSTRAP_TOKEN` unset.
- **Port 3000 refused** — `ui-build` still running or failed; check its log.
- **401 on every API call** — token mismatch between shell and `.env`.
- **Container healthy, dashboard blank** — `ui-build` exited non-zero;
  `docker compose up ui-build` to re-run it and read the failure.
- **Windows/IIS target fails** — this is known territory; go to
  `PILOT_KNOWN_GAPS.md` and `docs/ops/WINRM_ENABLEMENT.md` before debugging.

**Escalation.** Redact before sending anything: **never** send private keys,
`.env`, the keystore passphrase, backup bundles, or credential values. Logs
and `/readyz` output are safe to share. Send: what you did, what you
expected, `/api/v1/meta` output, the relevant log window. Related runbooks:
`INCIDENT_RESPONSE.md`, `KEY_ROTATION.md`, `DR_RUNBOOK.md`,
`WINRM_ENABLEMENT.md`, `WINDOWS_ACCESS_MATRIX.md`.

## 9. Pilot success and kill metrics (14–21 days)

> **Assumed — not sourced from an Experiment A outline.** No such document
> exists in this repository; these are a coherent default derived from what
> the product actually does, and they need the operator's real numbers before the
> pilot starts. Agree them with the design partner **in writing on day zero**
> — a metric adopted after the fact measures nothing.

Decide at day 14, extend to 21 only if a single named blocker is being fixed.

**Success — all of these:**

| # | Metric | Bar |
|---|---|---|
| S1 | Time to first issued certificate from a clean tarball | ≤ 60 min, unassisted, on day one |
| S2 | Estate discovered | ≥ 90% of the certificates the partner already knew about, plus ≥ 1 they did not |
| S3 | Certificates under management | ≥ 10 issued or imported and visible in inventory |
| S4 | Alerting is real | ≥ 1 expiry alert delivered to their own channel and acknowledged in-product |
| S5 | Automation proven once | ≥ 1 end-to-end renewal executed (SSH-push target) with no manual step |
| S6 | It stays up | Operator restarts the stack ≤ 1 time for a fault, in 14 days |
| S7 | Restore | One backup restored successfully in a scratch stack |
| S8 | Intent | Partner says, unprompted, they want to keep running it after the pilot |

**Kill — any one of these:**

| # | Signal | Threshold |
|---|---|---|
| K1 | Cannot complete day one without the vendor driving the keyboard | day 3 |
| K2 | Any incorrect cryptographic outcome — bad chain, wrong key usage, an accepted signature that should have failed | immediate, no threshold |
| K3 | Private key material or a credential appearing in a log, API response, or the UI | immediate |
| K4 | Data loss: an issued certificate or CA missing from inventory after a restart or restore | immediate |
| K5 | Operator stops opening the dashboard | 7 consecutive days |
| K6 | Discovery misses the majority of a known estate, or floods the operator with findings they call noise | day 14 |
| K7 | The blocking gap for their environment is on the Hypotheses list, not the Facts list — i.e. we would have to build, not configure | day 14 |
| K8 | ≥ 3 distinct P1 defects with no workaround inside 14 days | day 14 |

Record the reading against each row on day 14 with the actual number, not an
adjective. A pilot that ends "it went well" produced no evidence.
