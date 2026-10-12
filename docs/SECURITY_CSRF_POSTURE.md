# CSRF Posture

## Enforced posture: Bearer token + same-origin

Kryptkeeper does **not** use traditional synchroniser-token or double-submit cookie CSRF mitigations.
Instead it relies on two controls that together eliminate CSRF for browser clients:

### 1. Bearer token authentication (not cookies)

All authenticated API requests must include an `Authorization: Bearer <jwt>` header.
Tokens are stored in `sessionStorage` (see `ui/src/pages/Login.tsx`), which is:

- **not** accessible to cross-origin JavaScript
- **not** automatically attached to cross-origin requests by the browser (unlike cookies)

A cross-origin attacker page cannot read `sessionStorage` or inject the token into a forged
request, so the server never receives a valid `Authorization` header for a CSRF attempt.

### 2. Same-origin enforcement

The API does not set `Access-Control-Allow-Origin: *`.
Requests from foreign origins are rejected at the CORS layer before reaching any handler.

### Protocol endpoints (ACME, SCEP, EST, OCSP, CRL, CMP, XCEP)

These endpoints use client-certificate or challenge-based authentication, not browser sessions.
They are not exposed to browser CSRF vectors.

### Residual risk

| Scenario | Risk | Mitigation |
|---|---|---|
| Token leak via XSS | High if it occurs | CSP headers on the UI (planned); token is JWT with short TTL |
| Subdomain takeover + sessionStorage scope | Low | Subdomain isolation; `sessionStorage` is per-origin |
| HTTP (non-TLS) deployment | High | Deployment guide requires TLS; see `cmd/kryptkeeper/main.go` TLS flag |

### Testing

The absence of CSRF tokens is verified in `internal/bootstrap/auth_handlers_test.go` which
checks that unauthenticated requests without an `Authorization` header return 401 across all
state-mutating endpoints.

## Decision record

- **Date:** 2026-04-17
- **Decision:** Bearer + same-origin is the enforced CSRF posture; no CSRF token needed.
- **Rationale:** Matches industry practice for SPA + REST APIs (OWASP recommends this as an
  acceptable alternative to CSRF tokens when cookies are not used for auth transport).
- **Owner:** Security team
