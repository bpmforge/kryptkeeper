# Container Baseline Contract (WS-09)

Status: Phase 4 (WS-09 incremental)

## Scope

- Root `Dockerfile` provides real-mode app build and placeholder fallback mode.
- Root `docker-compose.yml` provides local runtime profile for the bootstrap service.

## Security/Runtime Baseline

- Runtime image: distroless non-root (`USER nonroot:nonroot`).
- Healthcheck binary included and wired (`/healthcheck`).
- Compose service uses:
  - `read_only: true`
  - `tmpfs: /tmp`
  - `security_opt: no-new-privileges:true`

## Local Compose Contract

- Service name: `kryptkeeper`
- Port mapping: `127.0.0.1:8080:8080` (loopback-only local exposure)
- Default local auth profile:
  - `AUTH_MODE=${AUTH_MODE:-bootstrap}`
  - `APP_BOOTSTRAP_TOKEN` is required via environment substitution (no static in-file token)

Runtime hardening in compose profile:

- `cap_drop: [ALL]`
- `restart: "no"` (surface failures clearly in local/dev)

## Compatibility Notes

- This baseline is additive and does not alter API contracts.
- Runtime smoke and protocol/integration harness remain the verification sources for WS-09 changes.
