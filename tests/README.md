# Test Harness

The `scripts/test/run.sh` suites below are the fast, hermetic checks run by CI. Real-client suites (certbot, lego, openssl, OpenSSH, SoftHSM2, kind, and others) live under `tests/live/`, each with its own README.

## Suites

- `tests/protocol/run.sh`
  - validates migration SQL integrity for `internal/db/migrations/{sqlite,postgres}`
    - every `.up.sql` has matching `.down.sql`
    - every `.down.sql` has matching `.up.sql`
    - migration names match `NNNNNN_description` and versions are sequential
  - Protocol conformance against real clients is in `tests/live/acme` and `tests/live/protocols`, not here.

- `tests/integration/run.sh`
  - runs concrete integration safety checks:
    - sqlite migration smoke apply/rollback for W1..W7 (when `sqlite3` is installed)
    - GitHub workflow YAML parse checks in `.github/workflows/*.{yml,yaml}` (when parser exists)

- `tests/smoke/run.sh`
  - supports runtime smoke (the local run covers far more than the checks listed here; 331 assertions as of 2026-10-09) in two modes:
    - `KRYPTKEEPER_SMOKE_MODE=auto` (default):
      - prefers **local binary smoke** when `go.mod` and `cmd/kryptkeeper` exist
      - falls back to deployment smoke when local prerequisites are absent
    - `KRYPTKEEPER_SMOKE_MODE=local`:
      - builds `./cmd/kryptkeeper` to a temp binary
      - starts the app on a random free localhost port
      - checks `GET /healthz` returns `200` and JSON containing `{"status":"ok"}`
      - checks `GET /readyz` returns `200` and JSON containing `{"status":"ready"}`
      - checks `GET /` returns `200` and text containing `kryptkeeper bootstrap app`
      - checks non-GET (`POST`) to `/healthz` returns `405`
      - checks authz in bootstrap mode (existing token flow)
      - checks authz in jwt mode (HS256 bearer token when token tooling is available)
      - checks authz in oidc mode with inline JWKS JSON
      - checks protected resource ping (`GET /api/v1/protected/ping`) across bootstrap/jwt/oidc paths:
        - missing bearer token => `401`
        - valid bearer token => `200` with `status:"ok"` and non-empty mode principal
        - non-GET (`POST`) => `405`
      - checks protected whoami (`GET /api/v1/protected/whoami`) across bootstrap/jwt/oidc paths:
        - missing bearer token => `401`
        - valid bearer token => `200` containing `resource`, `principal`, `auth_mode`, and `timestamp`
        - non-GET (`POST`) => `405`
      - checks protected config (`GET /api/v1/protected/config`) across bootstrap/jwt/oidc paths:
        - missing bearer token => `401`
        - valid bearer token => `200` containing `resource`, `auth_mode`, and mode-specific config booleans
          (`oidc_enabled`, `discovery_enabled`, `jwt_mode_enabled`), where `discovery_enabled` is only true when active OIDC discovery/JWKS refresh is enabled
        - non-GET (`POST`) => `405`
      - checks protected cert summary (`GET /api/v1/protected/certs/summary`) across bootstrap/jwt/oidc paths:
        - missing bearer token => `401`
        - valid bearer token => `200` containing `resource`, `principal`, deterministic summary values
          (`total=42`, `expiring_30_days=7`, `expired=2`), and `source:"file-store"`
        - non-GET (`POST`) => `405`
      - optionally checks OIDC discovery + JWKS rotation path (python3-backed local provider)
      - cleans up processes and temp artifacts automatically
    - `KRYPTKEEPER_SMOKE_MODE=deploy`:
      - uses existing env-based deployment smoke flow via `scripts/deploy/smoke.sh`

## Failure semantics

- Real check failures return **non-zero** and fail the suite.
- Missing optional runtime dependencies/configuration (for example `sqlite3`, parser runtime, local Go toolchain, or smoke target env) emit **WARN** and skip safely with zero.

## Smoke env knobs (local mode)

- `KRYPTKEEPER_SMOKE_OIDC_DISCOVERY_MODE=auto|on|off`
  - `auto` (default): run discovery/JWKS rotation smoke when tooling is present.
  - `on`: same as auto today (still skip-safe if tooling is unavailable).
  - `off`: skip discovery/JWKS rotation checks.
- `KRYPTKEEPER_SMOKE_OIDC_REFRESH_SECONDS=<int>`
  - Sets the OIDC JWKS cache refresh window used by the local discovery rotation check.
  - Harness passes this through to app env `APP_OIDC_JWKS_TTL_SEC`.

## Stable runner

Use `scripts/test/run.sh` as the top-level runner. CI calls this script.

## Commands

```bash
# all suites
scripts/test/run.sh

# individual suites
scripts/test/run.sh --suite protocol
scripts/test/run.sh --suite integration
scripts/test/run.sh --suite smoke

# smoke suite in local runtime mode (build + run bootstrap app)
KRYPTKEEPER_SMOKE_MODE=local scripts/test/run.sh --suite smoke

# smoke suite local mode with explicit auth bootstrap token override
APP_BOOTSTRAP_TOKEN=my-local-bootstrap-token \
  KRYPTKEEPER_SMOKE_MODE=local \
  scripts/test/run.sh --suite smoke

# smoke suite local mode in jwt auth mode (direct app run example)
AUTH_MODE=jwt \
APP_JWT_HS256_SECRET=my-local-jwt-secret-0123456789abcdef \
APP_JWT_ISSUER=my-local-issuer \
APP_JWT_AUDIENCE=my-local-audience \
go run ./cmd/kryptkeeper

# smoke suite local mode in oidc auth mode (direct app run example)
AUTH_MODE=oidc \
APP_OIDC_ISSUER=https://idp.example.com \
APP_OIDC_AUDIENCE=kryptkeeper \
APP_OIDC_JWKS_JSON='{"keys":[{"kty":"RSA","kid":"local-dev-kid","alg":"RS256","use":"sig","n":"<base64url-modulus>","e":"AQAB"}]}' \
go run ./cmd/kryptkeeper

# smoke suite local mode with OIDC discovery/JWKS rotation check enabled
# (auto by default when python3 exists)
KRYPTKEEPER_SMOKE_MODE=local \
KRYPTKEEPER_SMOKE_OIDC_DISCOVERY_MODE=auto \
KRYPTKEEPER_SMOKE_OIDC_REFRESH_SECONDS=1 \
scripts/test/run.sh --suite smoke

# disable discovery/JWKS rotation smoke explicitly
KRYPTKEEPER_SMOKE_MODE=local \
KRYPTKEEPER_SMOKE_OIDC_DISCOVERY_MODE=off \
scripts/test/run.sh --suite smoke

# smoke suite local mode still runs through both bootstrap and jwt checks
# plus oidc checks with ephemeral RS256 token/JWKS and optional discovery rotation
# (jwt/oidc/discovery checks skip safely when local token tooling is unavailable)
KRYPTKEEPER_SMOKE_MODE=local scripts/test/run.sh --suite smoke

# smoke suite auto mode (default: local first, then deploy fallback)
KRYPTKEEPER_SMOKE_MODE=auto scripts/test/run.sh --suite smoke

# smoke suite deploy mode (keeps existing deploy smoke path)
KRYPTKEEPER_SMOKE_MODE=deploy \
  KRYPTKEEPER_SMOKE_TARGET_ENV=staging \
  KRYPTKEEPER_SMOKE_BASE_URL_STAGING=https://staging.example.com \
  scripts/test/run.sh --suite smoke
```
