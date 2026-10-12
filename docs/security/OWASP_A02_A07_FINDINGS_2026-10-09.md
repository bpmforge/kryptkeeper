# OWASP A02 + A07 FINDINGS 2026-10-09 (kryptkeeper, --deep, focused slice)

Scope: A02 Cryptographic Failures and A07 Identification and Authentication Failures. A01 is out of scope (another agent covers it).
Dedup baseline: OWASP-001..004, SEMGREP-001..014, LLM-001..006 and SEC/DEP items are not re-raised. Cookie `Secure` is OWASP-004, the cert-manager skip-verify is SEMGREP-003, and the agent token in the log is SEMGREP-004.
Proof method: temp Go tests in `internal/bootstrap/zz_owasp_a02a07_tmp_test.go` (5 tests, all PASS with "PROVEN" logs, file deleted afterwards), or reading the code path end to end as noted for each finding.

## REAL findings

### A2A7-001: Key escrow and full-store backup bypass key dual control (single-admin private-key egress)
- severity: HIGH | category: owasp-web (A02) | tool: manual | status: REAL
- file: internal/bootstrap/handlers_key_escrow.go:42-77 (authorize at :17-31); internal/bootstrap/handlers_backup.go:36-83
- evidence:
  - `/api/v1/keys/{id}/export` routes through `dualControl` when `KRYPTKEEPER_KEY_DUAL_CONTROL=true` (handlers_keys.go:297-316).
  - `/api/v1/keys/escrow` and `/api/v1/admin/backup` only check `isAdminRole`. Neither file references `dualControl`.
  - In escrow, the same request body supplies `custodian_a_passphrase` and `custodian_b_passphrase`. `EscrowKey` (keystore/escrow.go:118-124) requires only that the two passphrases differ.
  - The design says otherwise. D-051 and FR-P13 say "escrowed encrypted and recovered under dual control", and FR-P50 says export is "a destructive key op requires a second approver".
- proof: (a) bypass by code read. `grep dualControl` matches handlers_keys.go but finds nothing in handlers_key_escrow.go or handlers_backup.go. (b) temp test `TestTmpOWASP_EscrowSingleActorRecoversKey`: one actor holding both passphrases ran `EscrowKey(store,"k1","a","b")` and then `RecoverEscrowedKeyMaterial(bundle,"a","b")`, which returned a parseable PKCS#8 private key (138 bytes). PASS. The test is a library call, so the env flag it set was not exercised. Part (a) is what shows the handler never consults dual control.
- preconditions: ["pki-admin credential (any single admin)", "KRYPTKEEPER_KEY_DUAL_CONTROL=true is what is being bypassed"]
- yields: ["plaintext private key of any extractable key (escrow)", "every extractable key in the store (backup)"]
- asset: keystore private keys, including CA keys
- remediation: Route escrow and backup through `KeyDualControl` (new action types `key_escrow` and `key_backup`) when it is enabled. Each custodian passphrase should come from a different authenticated principal, for example through two-step share submission.

### A2A7-002: Local login password verifier is a single HMAC-SHA256 with no work factor
- severity: MEDIUM | category: owasp-web (A02) | tool: manual | status: REAL
- file: internal/bootstrap/auth_identity.go:86 (`apiKeyVerifier(password, loginPepper)`), verifier defined at :70
- evidence: `APP_AUTH_LOGIN_PASSWORD_HASH` is compared against `hex(HMAC-SHA256(pepper, password))`. There is no bcrypt, scrypt or argon2, even though argon2id is already used in keystore/escrow. The pepper is stored in the same environment as the hash, so leaking the env or the config exposes both.
- proof: temp test `TestTmpOWASP_PasswordVerifierIsFastHMAC` measured 328ns per guess on one core (about 3M guesses/s/core). PASS.
- preconditions: ["read access to hub env/config (APP_AUTH_LOGIN_PASSWORD_HASH + APP_AUTH_LOGIN_PEPPER)"]
- yields: ["offline-cracked pki-admin password (default APP_AUTH_LOGIN_ROLE=pki-admin)"]
- asset: local admin credential
- remediation: Store an argon2id or bcrypt PHC string and verify it with the library's constant-time check. Keep the pepper as an optional HMAC pre-step.

### A2A7-003: Logout revokes nothing; refresh tokens rotate indefinitely
- severity: MEDIUM | category: owasp-web (A07) | tool: manual | status: REAL
- file: internal/bootstrap/handlers_auth.go:125 (logout handler); auth_identity.go:115 (Refresh)
- evidence:
  - Logout only clears the cookie. The access JWT has no `jti` and there is no deny-list.
  - `refreshSessions` is not touched on logout, and no endpoint revokes a refresh token.
  - `Refresh` mints a new refresh token with a fresh `refreshTTL` on every call, so there is no absolute session lifetime.
  - The deprovisioned check is the only revocation. It does not apply to the env-configured local user, who is not in the UserProvider.
- proof: temp test `TestTmpOWASP_LogoutDoesNotRevoke`: Login, then POST /api/v1/auth/logout (204). After that the same access token still authenticated through `authenticateBootstrap`, and `Refresh(refresh)` still succeeded. PASS.
- preconditions: ["attacker obtained a refresh token or access JWT (XSS, log, shared machine)"]
- yields: ["persistent session that survives user logout, extendable forever via refresh"]
- asset: user sessions (local login: pki-admin)
- remediation: Have logout delete the presented refresh token from `refreshSessions`. Add a `jti` and a short deny-list, or a per-subject session epoch. Cap the absolute refresh-chain lifetime.

### A2A7-004: Unknown `kid` forces an unthrottled JWKS refetch (unauthenticated outbound amplification and auth lock contention)
- severity: MEDIUM | category: owasp-web (A07/A02) | tool: manual | status: REAL
- file: internal/bootstrap/auth_oidc.go:119 (`validateOIDCRS256JWTManaged`); getJWKS (auth_oidc.go:39) holds `c.mu.Lock()` across the HTTP fetch
- evidence:
  - `exp`, `iss` and `aud` are checked before the signature, and an attacker can forge all of them because the payload is unsigned.
  - A random `kid` returns `errJWKSKeyNotFound`, which triggers `getJWKS(forceRefresh=true)`. That refetches both discovery and the JWKS under the cache write lock, which has a 2s timeout.
  - The refetch is not rate-limited or cooled down. This applies to every bearer request when AUTH_MODE=oidc.
- proof: temp test `TestTmpOWASP_JWKSForcedRefreshAmplification`: 50 forged unauthenticated tokens produced 102 outbound IdP requests. PASS.
- preconditions: ["AUTH_MODE=oidc with discovery (no static APP_OIDC_JWKS_JSON)", "network reach to hub API"]
- yields: ["2 outbound IdP requests per unauthenticated request", "serialised OIDC auth (DoS) / IdP rate-limit exhaustion"]
- asset: availability of authentication
- remediation: Add a minimum interval between forced refreshes (for example 30-60s) and coalesce concurrent refreshes. Do not hold the lock during the fetch.

### A2A7-005: Post-SSO redirect allows `/\host`, which browsers treat as an off-site redirect
- severity: LOW | category: owasp-web (A07) | tool: manual | status: REAL
- file: internal/bootstrap/auth_saml.go:112 (`safeRelativeRedirect`), used at :151 (RelayState out) and :278 (RelayState in at ACS)
- evidence: The check rejects only a leading `//`. `/\evil.example` passes, and `http.Redirect` emits it unchanged. Browsers normalise `\` to `/` and navigate to `//evil.example`.
- proof: temp test `TestTmpOWASP_SafeRelativeRedirectBackslash`: Location=`/\evil.example/x`. PASS.
- preconditions: ["SAML login enabled", "victim follows /api/v1/auth/saml/login?redirect=/%5Cevil.example"]
- yields: ["open redirect immediately after a successful SSO login (phishing / credential re-prompt)"]
- asset: user trust / SSO flow
- remediation: Reject `\` anywhere in the redirect, or parse it and require an empty Host and Scheme after replacing `\` with `/`.

### A2A7-006: OIDC login links accounts by unverified `email` claim, and the link is permanent
- severity: MEDIUM (conditional on IdP) | category: owasp-web (A07) | tool: manual | status: REAL (code path); exploitability depends on the IdP
- file: internal/bootstrap/auth_oidc_login.go:496-528 (email claim :496 → `resolveOIDCUser` → `findUserByEmail` → `LinkOIDCIdentity`)
- evidence:
  - If no `(iss,sub)` link exists, the callback resolves the user by the `email` claim alone. A search of internal/ and cmd/ finds no `email_verified` check.
  - It then permanently binds that IdP subject to the matched account (`user_db_provider.go:164`), so it inherits the account's role.
- proof: code path read end to end. `grep -rn email_verified internal cmd` finds 0 non-test hits.
- preconditions: ["IdP lets users set or change their email without verification (multi-tenant/social IdPs, some Keycloak/Auth0 configs)", "target account has not logged in via OIDC yet"]
- yields: ["takeover of a SCIM-provisioned account (incl. pki-admin) on first OIDC login"]
- asset: user accounts
- remediation: Require `email_verified == true` before falling back to email, or require a pre-provisioned `(iss,sub)` link.

### A2A7-007: OIDC `state` is not bound to the browser (login CSRF); no `nonce`
- severity: LOW | category: owasp-web (A07) | tool: manual | status: REAL
- file: internal/bootstrap/auth_oidc_login.go:390 (`stateStore.put`, server-side only), :455 (`stateStore.take`)
- evidence:
  - `state` is kept in a server-global map with no cookie or session binding, so any browser can redeem any outstanding state.
  - An attacker can start a login, authenticate at the IdP as themselves, and hand the victim the callback URL. The victim's browser is then logged into the attacker's account.
  - PKCE does not help here because the verifier is held by the hub, not the browser.
  - No `nonce` is sent or checked.
- proof: code path read (login → put, callback → take). No `Set-Cookie` and no nonce in either handler.
- preconditions: ["OIDC login enabled", "victim clicks attacker link"]
- yields: ["victim operates hub under attacker's identity (actions/audit misattributed)"]
- asset: session integrity / audit attribution
- remediation: Set a `__Host-` cookie holding a hash of state, compare it at the callback, and add and verify `nonce`.

### A2A7-008: SAML ACS has no replay protection
- severity: LOW | category: owasp-web (A07) | tool: manual | status: REAL
- file: internal/bootstrap/auth_saml.go:164 (ACS handler)
- evidence:
  - The handler does not cache Assertion or Response IDs and does not check `InResponseTo`, because the login does not store an AuthnRequest ID.
  - gosaml2 v0.11.0 checks time, audience and signature (handled correctly, e.g. :226) but has no replay cache.
  - A captured SAMLResponse is therefore replayable until NotOnOrAfter.
- proof: code path read. The handler has no ID store, and `BuildAuthURL` returns no request ID that is kept.
- preconditions: ["attacker captures a SAMLResponse (proxy log, browser history of POST, malware)"]
- yields: ["session as that user within assertion validity window"]
- remediation: Keep a TTL'd set of assertion IDs, and track and require `InResponseTo` for SP-initiated flows.

### A2A7-009: Minor A02/A07 hygiene (LOW, grouped)
- auth_bootstrap.go:45: `token == cfg.bootstrapToken` is a non-constant-time compare of the super-admin bootstrap token. Use `subtle.ConstantTimeCompare`.
- auth.go:214, auth_identity.go:140 and handlers_auth.go:213 (impl :447): the deprovisioned check fails open. If `ListUsers` errors (for example a DB outage), deprovisioned users are accepted.
- auth_config.go:108 (NewAuthenticatorFromEnv): there is no minimum length or entropy check on `APP_BOOTSTRAP_TOKEN`, `APP_JWT_HS256_SECRET`, `APP_AUTH_LOGIN_SIGNING_SECRET`, `APP_API_KEY_PEPPER` or `APP_SCIM_BEARER_TOKEN`. A short HS256 secret can be brute-forced offline from any issued JWT.
- auth.go:313 (`case "oidc"`): in AUTH_MODE=oidc, an unset `APP_OIDC_AUDIENCE` and `APP_OIDC_ISSUER` silently disable the aud/iss checks, so tokens the IdP issued to any client are accepted. The config should fail closed.
- handlers_auth.go:59 and auth_identity.go:83-86: login is rate-limited per IP only (10/min) with no per-account lockout. The email-mismatch path returns before the HMAC, which is a timing difference that reveals the single configured email.

## Checked, no finding
- HS256 JWT (auth_hs256.go): `alg` is pinned to HS256 (rejects none and RS/HS swap), the signature uses `hmac.Equal`, `exp` is required, and iss/aud are checked when configured.
- OIDC RS256 (auth_jwks.go): `alg` is pinned to RS256, `kid` is required, `kty` must be RSA, and the exponent is validated. Discovery and JWKS URLs must be https, and bodies are limited to 1 MiB.
- PKCE S256 with a 32-byte verifier. The state is 24 bytes from crypto/rand, single-use, TTL'd and capped at 4096.
- SAML: `ResponseSignatureValidated`, InvalidTime and NotInAudience are all enforced. gosaml2 v0.11.0 and goxmldsig v1.6.0 are past the known XSW CVEs.
- API keys: HMAC-SHA256 with a pepper, a constant-time compare, and expiry is enforced. The key fails closed without a pepper. The secret has 144 bits of entropy.
- SCIM bearer: constant-time compare, and fails closed when unset (auth_oidc_login.go:570-580).
- Agent tokens are stored as SHA-256 and compared in constant time. The enrollment secret is compared in constant time (agent_attestation.go:73). Open registration is SEMGREP-011.
- Keystore and escrow KDF: argon2id (t=2, m=64MiB, p=4) with AES-256-GCM and per-envelope salt and nonce. Escrow shares are AAD-bound to key id and slot.
- Randomness: no `math/rand` in internal/ or cmd/. CA serials are 128-bit from crypto/rand (ca/engine.go:873). Root `MaxPathLen` is 1.
- TLS: the hub server has MinVersion TLS1.2 (cmd/kryptkeeper/tls.go:126). The only InsecureSkipVerify uses outside scanners and the documented fingerprint verifier are SEMGREP-003 (already raised). certmanagerissuer/k8sclient.go:54 and discovery/servicemesh.go:91 set RootCAs without MinVersion, which defaults to TLS1.2 in Go 1.26 (INFO).
- Renewal keygen uses ECDSA P-256 or RSA-2048 from crypto/rand. The key is zeroised and pushed to the target by design. The log, audit, and SSE sweep found no key, passphrase or token values in log or audit format args (apart from SEMGREP-004).
- Key export: dual control, a 4 KiB body cap, the passphrase is required, and the export is audited without key bytes.

## Not covered
- Leaf-escrow (handlers_key_custody_ops.go:90-140) and BYOK export (handlers_byok.go:61, canApproveActions) were not checked for single-actor dual-control bypass. They may share A2A7-001's class.
- The SPIFFE `key_pem` response is SEMGREP-010 and was not re-examined.

# Completion Manifest
## Files produced
- docs/security/OWASP_A02_A07_FINDINGS_2026-10-09.md: A02/A07 findings (1 HIGH, 4 MEDIUM, 4 LOW groups)
## Files modified
- None (the temp test internal/bootstrap/zz_owasp_a02a07_tmp_test.go was created and deleted)
## Decisions made
- A2A7-001 is rated HIGH even though it needs pki-admin. Dual control exists specifically to stop a single admin, and the bypass yields plaintext private keys, which violates a CLAUDE.md law.
- A2A7-006 is MEDIUM only because exploitability depends on IdP email-verification behaviour.
## Known issues / deferred
- Leaf-escrow and BYOK single-actor check (see Not covered).
## Verify result
- PASS: 5 temp proof tests ran with `go test ./internal/bootstrap -run TestTmpOWASP_ -v` and all logged PROVEN. The test file was then deleted. Evidence: `docs/security/OWASP_A02_A07_FINDINGS_2026-10-09.md`
## Memory written
- None. Nothing durable beyond this file.
## Model tier: large, context used: medium
Maker: owasp-web-checker (A02/A07 slice)
Verifier: none independent yet (attack-chainer / coordinator)
## Ready for: owasp-web-checker merge into OWASP_TRACKER, then attack-chainer

owasp-a02-a07 done -- A02 confidence 7/10, A07 confidence 8/10
