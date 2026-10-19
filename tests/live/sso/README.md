# SSO live harness (Keycloak)

`bash tests/live/sso/run.sh` boots a real Keycloak in podman and a real hub,
then drives browser-style SSO with curl as the browser: OIDC login with
group-to-role mapping (W22-21), SAML login and a SCIM create-then-deactivate
timing check (W22-22). It proves the hub's code paths against a stand-in IdP.
It does **not** prove anything about Okta or Entra ID; those are manual, see
[`docs/release/SSO_UAT_RECORD.md`](../../../docs/release/SSO_UAT_RECORD.md).

## Run it

Prerequisites: podman (`/opt/homebrew/bin/podman` or on `PATH`), `openssl`,
`curl`, `jq`, `python3`, `go`. Free loopback ports 18443 (Keycloak) and 18090
(hub); override with `KK_SSO_KC_PORT` / `KK_SSO_HUB_PORT`. The first run pulls
`quay.io/keycloak/keycloak:26.0.8` (about 450 MB); Keycloak takes 30-90 s to
import the realm. The whole run takes about 8 minutes, most of it the
deliberate 20 s wait in the expired-assertion check and Keycloak start-up.

```bash
bash tests/live/sso/run.sh
```

Exit status is non-zero if any step fails; the last line is
`=== RESULT: N passed, M failed ===`. On failure the tail of the hub log is
printed before cleanup.

## What it checks

| Part | File | Assertions |
|------|------|-----------|
| Setup | `lib.sh` | Keycloak realm `kk` imports and serves discovery; hub builds and is healthy over TLS verified against its own exported CA |
| OIDC (W22-21) | `oidc.sh` | alice (kk-admins), bob (kk-operators), carol (kk-auditors) log in through the real authorization-code + PKCE flow and `whoami` shows `pki-admin`, `pki-operator`, `auditor`; dave (kk-nobody) gets 403 and no cookie; a replayed callback URL and a callback with a mutated `state` get 401; with `APP_AUTH_UNMAPPED_ROLE=read-only` dave logs in as `viewer` |
| SAML (W22-22) | `saml.sh` | alice and bob log in over SAML with the mapped role (the control); the same SAMLResponse posted twice gets 401 the second time; a response posted 20 s after issue (lifespan 8 s) gets 401; an IdP-initiated response from `kk-sp` is accepted (control) and the same from `kk-other` (wrong audience) gets 401; dave gets 403 |
| SCIM (W22-22) | `scim.sh` | the script plays the IdP: create erin (201), OIDC login as erin, `PATCH active=false`, then poll the old session cookie every 5 s up to 900 s and print the seconds until it gets 401; a fresh login for erin is 401 |

A rejection only counts because a control proves the same path accepts a good
request first (the successful logins; the `kk-sp` IdP-initiated response).

Users are created through SCIM before any login, because the login flows never
create accounts. Roles come from the `groups` claim/attribute through
`APP_AUTH_ROLE_MAP_JSON` (W22-19).

## How the pieces are wired

- **Keycloak** runs as a uniquely named container (`kk-w22-sso-keycloak-<pid>`)
  published on `127.0.0.1` only, with `--import-realm` from
  `realm/kk-realm.json`. The SAML clients and user erin are added later through
  the admin API's partial import (`realm/saml-clients.json`).
- **The hub** is a host process (`go build ./cmd/kryptkeeper`) on a persistent
  data dir under the work dir, so users survive the restarts the checks use to
  change one setting at a time. It serves self-issued TLS; every curl to it
  uses `--cacert` with the CA exported through EST `cacerts`. The only
  unverified request is the initial health probe used to fetch that CA.
- **Cleanup**: a trap stops the hub, removes only this run's container by its
  unique name, and deletes the work dir (under `$HOME`, because podman on macOS
  mounts only `$HOME`). No other container is touched.
- **Secrets**: the Keycloak admin password, the SCIM token and the hub's login
  signing secret are generated per run and never printed. The realm users'
  passwords (`<name>-fixture-pw`) and the `lab-hub` client secret are fixed test
  fixtures that exist only inside this harness.

## Deliberate differences from a production setup

- **Keycloak is plain HTTP on loopback** (`--http-enabled`, hostname
  `http://localhost:18443`). The hub accepts an `http://` IdP URL only for
  `localhost`/`127.0.0.1`, and on macOS Go ignores `SSL_CERT_FILE` (the system
  keychain is the only trust source), so a throwaway Keycloak CA cannot be
  given to the hub without editing the keychain. TLS verification of an IdP is
  therefore not exercised here. The hub's own listener is TLS.
- **The SAML client does not require signed AuthnRequests** (the hub sends
  unsigned ones). Keycloak signs both the response and the assertion; the hub
  requires the response-level signature.
- The expired-assertion case waits 20 s on purpose (assertion lifespan 8 s plus
  skew). The request id is still inside its 10-minute TTL then, so the 401 is
  the time check, not the request binding.
- The SCIM check measures time to refusal as seen by the hub, which checks the
  user store on every request; with a real IdP the delay before the
  deactivation arrives is the IdP's provisioning interval, which this harness
  does not model.

## Reading failures

| Symptom | Look at |
|---------|---------|
| `Keycloak container exited during startup` | the `kc:` lines printed above it (a realm file Keycloak rejected, usually) |
| `port ... already in use` | another process on 18443/18090; set `KK_SSO_KC_PORT` / `KK_SSO_HUB_PORT` |
| callback status 500/503 | the hub log tail printed at the end; check the issuer and discovery URL |
| SAML 401 on the control login | clock skew, the realm signing certificate, or `APP_SAML_*` values |
| dave gets 302 instead of 403 | the default unmapped policy changed (`APP_AUTH_UNMAPPED_ROLE`) |

## Result of the live run

Run on 2026-10-15 (macOS, podman 6.1.3, Keycloak 26.0.8, hub built from this
branch). Output of `bash tests/live/sso/run.sh`:

```text

== start Keycloak (quay.io/keycloak/keycloak:26.0.8) as kk-w22-sso-keycloak-68866 on 127.0.0.1:18443 ==
PASS: Keycloak realm kk is serving discovery after ~27s

== build hub ==
PASS: hub built
PASS: hub healthy over verified TLS (pid 71605)

== OIDC: provision the fixture users over SCIM (login never creates accounts) ==
PASS: SCIM created alice@sso.test (201)
PASS: SCIM created bob@sso.test (201)
PASS: SCIM created carol@sso.test (201)
PASS: SCIM created dave@sso.test (201)

== OIDC: three mapped groups log in with the right role ==
PASS: alice: callback 302 with a kk_token session cookie
PASS: alice: whoami role = pki-admin
PASS: bob: callback 302 with a kk_token session cookie
PASS: bob: whoami role = pki-operator
PASS: carol: callback 302 with a kk_token session cookie
PASS: carol: whoami role = auditor

== OIDC: unmapped group is denied (default policy) ==
PASS: dave (kk-nobody): callback 403 and no kk_token cookie

== OIDC: a replayed or tampered state is rejected ==
PASS: replayed alice callback URL (state already consumed): 401
PASS: callback with a mutated state value: 401

== OIDC: APP_AUTH_UNMAPPED_ROLE=read-only is the explicit opt-in ==
PASS: hub healthy over verified TLS (pid 71933; extra env: APP_AUTH_UNMAPPED_ROLE)
PASS: dave with read-only opt-in: callback 302 with a session cookie
PASS: dave with opt-in: whoami role = viewer
PASS: hub healthy over verified TLS (pid 71981)

== SAML: import the SAML clients and point the hub at realm kk ==
PASS: Keycloak partial import: SAML clients kk-saml-sp, kk-saml-other and user erin ({"added":3,"skipped":0,"overwritten":0})
PASS: hub healthy over verified TLS (pid 72071; extra env: APP_SAML_LOGIN_ENABLED APP_SAML_IDP_SSO_URL APP_SAML_IDP_ISSUER APP_SAML_SP_ISSUER APP_SAML_AUDIENCE APP_SAML_ACS_URL APP_SAML_IDP_CERTIFICATE)

== SAML: mapped users log in with the right role (control for every rejection below) ==
PASS: alice: ACS 302 with a kk_token session cookie
PASS: alice via SAML: whoami role = pki-admin
PASS: bob: ACS 302 with a kk_token session cookie
PASS: bob via SAML: whoami role = pki-operator

== SAML: a replayed assertion is rejected ==
PASS: alice's identical SAMLResponse posted a second time: 401

== SAML: an expired assertion is rejected (assertion lifespan 8s) ==
(request id is still inside its 10 min TTL, so a 401 below is the assertion time check, not the request binding)
PASS: SAMLResponse posted 20s after issue (lifespan 8s): 401

== SAML: wrong audience is rejected (IdP-initiated control vs kk-other) ==
PASS: hub healthy over verified TLS (pid 73110; extra env: APP_SAML_LOGIN_ENABLED APP_SAML_IDP_SSO_URL APP_SAML_IDP_ISSUER APP_SAML_SP_ISSUER APP_SAML_AUDIENCE APP_SAML_ACS_URL APP_SAML_IDP_CERTIFICATE APP_SAML_ALLOW_IDP_INITIATED)
PASS: control: IdP-initiated response from kk-sp (audience kk-saml-sp) accepted: 302
PASS: IdP-initiated response from kk-other (audience kk-saml-other): 401
PASS: hub healthy over verified TLS (pid 73228; extra env: APP_SAML_LOGIN_ENABLED APP_SAML_IDP_SSO_URL APP_SAML_IDP_ISSUER APP_SAML_SP_ISSUER APP_SAML_AUDIENCE APP_SAML_ACS_URL APP_SAML_IDP_CERTIFICATE)

== SAML: unmapped group is denied ==
PASS: dave (kk-nobody) via SAML: ACS 403 and no kk_token cookie

== SCIM: create erin, log her in over OIDC, deactivate, time how long access survives ==
PASS: hub healthy over verified TLS (pid 73345)
PASS: SCIM created erin@sso.test (201)
PASS: erin: OIDC login 302, whoami role = pki-operator
PASS: SCIM PATCH active=false: 200 with active:false
PASS: erin's old session cookie returned 401 0s after SCIM deactivation (limit 900s)
PASS: erin: a fresh OIDC login after deactivation: 401

=== RESULT: 39 passed, 0 failed ===
```
