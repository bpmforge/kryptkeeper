# Live results: Keycloak SSO (OIDC and SAML), v0.21

Ticket W33-07. The harness itself is `tests/live/sso/` (W22-21/22); `tests/live/keycloak/run.sh` is the nightly wrapper. Nightly runs upload `last-run.md` as the `keycloak-sso-results` artifact; this document is filled in by hand (CI cannot push to main).

## Environment

| Item | Value |
|---|---|
| Host | macOS (Darwin 27.0.0), Apple Silicon, podman machine `podman-machine-default` (applehv, 12 CPU, 32 GiB) |
| Podman | 6.1.3 |
| Keycloak image | `quay.io/keycloak/keycloak:26.0.8` (already pulled locally) |
| Hub commit | `2aba78fe` (branch kk/w33-c, plus the W33-07 wrapper) |
| Ports | Keycloak 127.0.0.1:18443, hub 127.0.0.1:18090 |

## Command

`bash tests/live/keycloak/run.sh`

## Result

Exit code 0, wall time 2m39s, `=== RESULT: 39 passed, 0 failed ===`, wrapper counts OIDC role PASS lines 7, SAML role PASS lines 2.

| Leg | Check | Result |
|---|---|---|
| OIDC | alice whoami role = pki-admin | PASS |
| OIDC | bob whoami role = pki-operator | PASS |
| OIDC | carol whoami role = auditor | PASS |
| OIDC | dave (unmapped group) callback 403, no session | PASS |
| OIDC | dave with `APP_AUTH_UNMAPPED_ROLE=read-only`: role = viewer | PASS |
| OIDC | replayed callback URL 401; mutated state 401 | PASS |
| SAML | alice via SAML role = pki-admin | PASS |
| SAML | bob via SAML role = pki-operator | PASS |
| SAML | replayed SAMLResponse 401; expired assertion 401; wrong audience 401; IdP-initiated control 302 | PASS |
| SAML | dave (unmapped group) ACS 403, no session | PASS |
| SCIM | create erin 201, OIDC login role = pki-operator, deactivate, old session 401 after 0s, fresh login 401 | PASS |

Wrapper guard check (stub `sso/run.sh`, not committed): a harness that prints a FAIL, and one that prints no SAML PASS line, both make the wrapper exit 1 with `FAIL: harness produced no OIDC/SAML pass lines`. The full-harness negative test (breaking a role mapping in a scratch copy of `oidc.sh`) was not run; the harness's own `FAIL` lines already drive a non-zero exit.

## Date

2026-10-17 (UTC)
