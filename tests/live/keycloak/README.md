# Keycloak live harness (W33-07)

Thin nightly wrapper over `tests/live/sso/` (W22-21/22), which boots a pinned
Keycloak (`quay.io/keycloak/keycloak:26.0.8`) under podman plus a real hub and
drives OIDC login (alice/bob/carol role mapping), SAML login and SCIM deactivation with curl.

    bash tests/live/keycloak/run.sh

Prerequisites: podman, openssl, curl, jq, python3, go. Loopback ports 18443
(Keycloak) and 18090 (hub; fixed in the SAML client fixture); 18443 is overridable
via `KK_SSO_KC_PORT`. Exit 0 only if every check passes and at least one OIDC and
one SAML role assertion ran. A summary is written to `last-run.md` (git-ignored,
override with `KK_KC_RESULTS`). The container is named per run and only that
container is removed on exit. Results: `docs/release/LIVE_RESULTS_KEYCLOAK_v0.21.md`.
