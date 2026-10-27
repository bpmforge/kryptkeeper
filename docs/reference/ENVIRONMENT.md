# Environment variables

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
| `KRYPTKEEPER_DB_MAX_OPEN_CONNS` / `KRYPTKEEPER_DB_MAX_IDLE_CONNS` | No | PostgreSQL pool size per store (defaults `3` / `1`); see [deployment.md](../deployment.md) |
| `KRYPTKEEPER_DB_DSN` / `DATABASE_URL` | If postgres | PostgreSQL connection string |
| `KRYPTKEEPER_KEY_BACKEND` | No | `software` (default, PKCS#8), `pkcs11`, `cloudkms` (with `KRYPTKEEPER_KMS_PROVIDER=aws\|gcp\|azure`), `vault` — see [Key Storage](#key-storage) for what is tested |
| `KRYPTKEEPER_KEYSTORE_PASSPHRASE` | **Yes** (software keystore) | Encrypts CA private keys at rest; required by Compose and must differ from `APP_BOOTSTRAP_TOKEN` |
| `KRYPTKEEPER_ALLOW_MISSING_CA_KEYS` | No | Recovery only: start even though an active CA has no key in the keystore (default: the hub refuses to start) |
| `KEYSTORE_SIGNER_TTL_MINUTES` | No | Idle eviction for decrypted CA signers (default 60) |
| `SIEM_WEBHOOK_URL` | No | Push cert lifecycle events to a webhook |
| `SIEM_SYSLOG_ADDR` | No | RFC 5424 syslog output (Splunk/QRadar) |
| `APP_VERSION` | No | Version string shown in `/api/v1/meta` |
