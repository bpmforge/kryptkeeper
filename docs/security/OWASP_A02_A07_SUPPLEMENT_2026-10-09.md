# OWASP A02/A07 supplement (2026-10-09)

A second, independent A02/A07 pass (a helper started by the first, interrupted
OWASP run) reported after the focused pass in
`OWASP_A02_A07_FINDINGS_2026-10-09.md`. It was read-only. Findings it shares
with the focused pass are cross-referenced; findings only it has are kept here
in full so the attack chainer and the fix backlog see them. Severities are its
own; the coordinator's adjustments are noted.

## Only in this pass

| ID | Sev | Location | Finding | Fix |
|---|---|---|---|---|
| A02-3 | MEDIUM (conditional) | auth_config.go:117,220; auth_validation.go:47; auth_bootstrap.go:59-65 | `APP_AUTH_LOGIN_SIGNING_SECRET` and `APP_JWT_HS256_SECRET` only have to be non-empty. Session JWTs carry a signed `role` claim, so anyone holding any session JWT (even a viewer) can brute-force a weak secret offline and mint `role: pki-admin`. Algorithm pinning itself is correct (HS256 only on that path, RS256 with required kid on the JWKS path, `exp` required, `hmac.Equal`). | Refuse to start with an HS256 secret under 32 bytes. |
| A02-4 | MEDIUM (conditional; coordinator: HIGH when AUTH_MODE=oidc with a public IdP) | auth_jwks.go:75-86; auth_hs256.go:66-78; auth.go:316-327 | With `AUTH_MODE=oidc` and an empty audience (or issuer), any token signed by the IdP's JWKS is accepted, for any client, as role service-account, which holds certificate.issue and certificate.renew. With a public IdP, any account at that IdP could issue certificates. `nbf` is never checked. Session JWTs are not bound to the deployment either (empty default issuer/audience). | In oidc mode, require issuer and audience at startup (fatal) and check `nbf`. |
| A07-4 | MEDIUM | handlers_pending_actions.go:164; handlers_auth.go:335; auth_identity.go:262 | Proposer != approver compares principal IDs, but an admin can mint API keys with any free-text `principal_id` and role pki-admin, then approve their own proposals (key export grant, key delete/rotate, plugin enable). The bootstrap token and a session are also two IDs for one person. Audited via `api-key.create`. Related: LLM-006 (operator approving what their agent proposed). | Bind API keys to existing user records; compare a canonical human identity; forbid approval by keys the proposer minted. |
| A07-6 | LOW | auth_bootstrap.go:45-46; cmd/kryptkeeper/main.go:232-239 | Bootstrap token compared with `==`, no strength check, cannot be turned off for SSO deployments (they run in AUTH_MODE=bootstrap); startup validation errors are logged, never fatal. | Constant-time compare, minimum 32 bytes, a way to disable it after setup, fatal config errors. |
| A07-7 | LOW | handlers_agents.go:244,254,266,526,665 | The in-memory agent store compares tokens with `!=` (the DB store hashes and compares in constant time). | Reuse `agentTokenMatches`. |
| A07-8 | LOW | handlers_auth.go:59; auth_rate_limit.go:165-175 | Login rate limit is per IP only (10/min); behind a proxy without `APP_TRUSTED_PROXY_CIDRS` everyone shares one bucket; no per-account backoff. | Per-account backoff. |
| SAML-F | functional | auth_saml.go | Requires a signed Response; IdPs that sign only the Assertion are rejected. | Accept a signed Assertion as well (with wrapping checks). |
| SPIFFE-L | LOW | handlers_spiffe.go:185,199; spiffe_workload.go | SEMGREP-010 (`key_pem` in responses) is accepted design (fresh per-request key, same model as SPIRE), but responses lack `Cache-Control: no-store`, `/workload-svid` has no rate limit, and an error leaks CA-engine text. | `no-store`, rate limit, generic error. |

## Shared with the focused pass (same issue, independent confirmation)

- A02-1 cookie `Secure` only from X-Forwarded-Proto = OWASP-004.
- A02-2 login password HMAC not a KDF = A2A7-002.
- A02-5 backup/escrow bypass dual control (dual control also off by default) = A2A7-001.
- A02-6 secret-bearing responses lack `no-store`; export passphrases have no minimum (adds to A2A7 LOWs).
- A07-1 SAML RelayState `/\host` open redirect = A2A7-005 (this pass rates it MEDIUM).
- A07-2 SAML no InResponseTo / replay cache = A2A7-008 (this pass rates it MEDIUM, conditional).
- A07-3 OIDC link by unverified email, persisted = A2A7-006.
- A07-5 logout does not revoke refresh; refresh keeps the login-time role = A2A7-003.

## Checked and passing (this pass)

API-key verifier and constant-time compare; SCIM bearer and agent enrollment
secret constant-time; config API never returns secret values; credential
preflight never returns the secret; hub TLS min 1.2; OIDC endpoints required
https; no dev-login code path (SEC-03 is a dev script seeding the normal,
off-by-default local login). Keystore crypto: Argon2id (t=2, 64 MB, p=4),
AES-GCM with random salt and nonce, empty passphrase rejected; minor: backup
and export seal without AAD (software.go:456).

Confidence reported: A02 7/10, A07 7/10.
