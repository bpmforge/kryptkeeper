# WS-01 / WS-02 Focused Security Audit (Latest)

## Scope

- `internal/bootstrap/middleware_request_id.go`
- `internal/bootstrap/response.go`
- `internal/bootstrap/auth.go`
- `internal/bootstrap/auth_config.go`
- `internal/bootstrap/auth_identity.go`
- `internal/bootstrap/auth_rate_limit.go`
- `internal/bootstrap/handlers_auth.go`
- `internal/bootstrap/authz_ops.go`
- `internal/bootstrap/server.go`
- `internal/bootstrap/handlers.go`

## Summary

- CRITICAL: 0
- HIGH: 0
- MEDIUM: 3
- LOW: 1

Re-audit update:

- Prior HIGH on broad/default bind exposure is resolved after bind-address hardening.
- Evidence:
  - `cmd/kryptkeeper/main.go` now defaults to `APP_BIND_ADDR=127.0.0.1` when unset.
  - `docker-compose.yml` keeps host exposure loopback-only (`127.0.0.1:8080:8080`) and sets container bind explicitly.

## Findings

### HIGH-1 (Resolved): Broad/default bind exposure risk for auth-bearing endpoints

- Previous location: `internal/bootstrap/server.go` call path via default listen address composition.
- Resolution: default listen host is now loopback unless explicitly overridden.
- Residual recommendation: enforce TLS termination policy in deployment environments where non-loopback bind is enabled.

### MEDIUM-1: Password verifier model uses fast hash semantics

- Location: `internal/bootstrap/auth_identity.go`
- Risk: Direct HMAC-based verifier lacks adaptive work factor/per-user salt typical for password KDFs.
- Recommendation: migrate to Argon2id/bcrypt-based verifier storage.

### MEDIUM-2: Login error distinction can enable account-state enumeration

- Location: `internal/bootstrap/handlers_auth.go`
- Risk: distinct invalid-credential vs inactive-account responses may leak account state.
- Recommendation: normalize auth failure response and keep specific reason in audit logs only.

### MEDIUM-3: IP-only rate limiting is bypass-prone and can cause NAT/proxy collateral lockout

- Location: `internal/bootstrap/handlers_auth.go`, `internal/bootstrap/auth_rate_limit.go`
- Risk: distributed attempts bypass limits; shared egress IPs can throttle legitimate users.
- Recommendation: composite limiter key (account + route + client IP), add progressive backoff.

### LOW-1: Non-positive rate-limit config allows requests

- Location: `internal/bootstrap/auth_rate_limit.go`
- Risk: future config drift could accidentally disable limit path.
- Recommendation: fail closed for invalid limits.

## Gate Impact

- No CRITICAL/HIGH blockers remain in this focused audit scope.
