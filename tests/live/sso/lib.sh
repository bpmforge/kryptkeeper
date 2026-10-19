#!/usr/bin/env bash
# Shared scaffolding for the SSO live harness (W22-21, extended by W22-22).
# Sourced by run.sh; never executed directly.
#
# What it gives the parts (oidc.sh, saml.sh, scim.sh): PASS/FAIL/STEP, a
# cleanup trap, start_keycloak, start_hub (re-runnable with extra env),
# kc_login (curl as the browser through the real authorization-code flow),
# hub_get, scim_post, ensure_users.
#
# Keycloak is reached over plain HTTP on loopback. That is deliberate and is
# the one place this harness departs from a fully-TLS IdP: the hub accepts an
# http:// IdP URL only for localhost / 127.0.0.1 (requireHTTPSURL in
# internal/bootstrap/auth_config.go), and on macOS Go ignores SSL_CERT_FILE
# (the system keychain is the only trust source), so a throwaway Keycloak CA
# cannot be handed to the hub without editing the user's keychain. The hub's
# own listener is TLS (self-issued) and every curl to it verifies against the
# hub's exported CA; there is no -k anywhere past the initial health probe.
#
# Secrets: the realm file and the user/client passwords are TEST FIXTURES.
# The Keycloak admin password, SCIM token and login signing secret are
# generated per run and never printed.

set -u
set -o pipefail

HERE="${HERE:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
PODMAN="${PODMAN:-/opt/homebrew/bin/podman}"
command -v "$PODMAN" >/dev/null 2>&1 || PODMAN="$(command -v podman || true)"

# Pinned Keycloak. 26.0.8 resolved and pulled on 2026-10-15.
KC_IMAGE="${KK_SSO_KC_IMAGE:-quay.io/keycloak/keycloak:26.0.8}"
KC_PORT="${KK_SSO_KC_PORT:-18443}"
HUB_PORT="${KK_SSO_HUB_PORT:-18090}"
KC_BASE="http://localhost:${KC_PORT}"
KC_REALM_URL="${KC_BASE}/realms/kk"
HUB_BASE="https://127.0.0.1:${HUB_PORT}"
KC_NAME="kk-w22-sso-keycloak-$$"
KC_CLIENT_SECRET="lab-hub-fixture-secret-not-real" # matches realm/kk-realm.json (fixture)

# podman on macOS only virtiofs-mounts $HOME, so the work dir lives there.
WORK="$(mktemp -d "$HOME/.kk-w22-sso.XXXXXX")"
HUB_DIR="$WORK/hub"
CA_PEM="$WORK/hub-ca.pem"
SCIM_TOKEN="$(openssl rand -hex 24)"
KC_ADMIN_PASS="$(openssl rand -hex 16)"
LOGIN_SIGNING_SECRET="$(openssl rand -hex 32)"

PASSED=0
FAILED=0
STEP() { echo; echo "== $* =="; }
PASS() { PASSED=$((PASSED + 1)); echo "PASS: $*"; }
FAIL() { FAILED=$((FAILED + 1)); echo "FAIL: $*"; }
DIE()  { FAIL "$*"; echo "=== RESULT: $PASSED passed, $FAILED failed ==="; exit 1; }

HUB_PID=""
stop_hub() {
  if [ -n "$HUB_PID" ]; then
    kill "$HUB_PID" >/dev/null 2>&1 || true
    wait "$HUB_PID" >/dev/null 2>&1 || true
    HUB_PID=""
  fi
}

cleanup() {
  local rc=$?
  trap - EXIT
  STEP "cleanup"
  if [ "$FAILED" -gt 0 ] && [ -f "$WORK/hub.log" ]; then
    echo "--- hub.log (last 25 lines, secrets are never logged) ---"
    tail -25 "$WORK/hub.log"
  fi
  stop_hub
  # Only this run's own container, by its unique name; nothing else is touched.
  "$PODMAN" rm -f "$KC_NAME" >/dev/null 2>&1 || true
  rm -rf "$WORK"
  exit "$rc"
}
trap cleanup EXIT

need() { command -v "$1" >/dev/null 2>&1 || DIE "missing prerequisite: $1"; }

port_free() { ! (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

# --- Keycloak ---------------------------------------------------------------

start_keycloak() {
  STEP "start Keycloak ($KC_IMAGE) as $KC_NAME on 127.0.0.1:$KC_PORT"
  port_free "$KC_PORT" || DIE "port $KC_PORT is already in use (set KK_SSO_KC_PORT)"
  mkdir -p "$WORK/realm"
  cp "$HERE/realm/kk-realm.json" "$WORK/realm/kk-realm.json"
  local sel=""
  [ -x /usr/sbin/getenforce ] && [ "$(/usr/sbin/getenforce 2>/dev/null)" = Enforcing ] && sel=":Z"
  # start (production mode) needs a hostname; --http-enabled is the explicit
  # loopback-only opt-in, the port is published on 127.0.0.1 only.
  "$PODMAN" run -d --name "$KC_NAME" -p "127.0.0.1:${KC_PORT}:8080" \
    -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD="$KC_ADMIN_PASS" \
    -v "$WORK/realm:/opt/keycloak/data/import:ro${sel}" \
    "$KC_IMAGE" start --import-realm --http-enabled=true --hostname="$KC_BASE" >/dev/null \
    || DIE "podman run failed for $KC_IMAGE"
  local i
  for i in $(seq 1 120); do
    if [ "$("$PODMAN" inspect -f '{{.State.Running}}' "$KC_NAME" 2>/dev/null)" != true ]; then
      "$PODMAN" logs --tail 25 "$KC_NAME" 2>&1 | cut -c1-240 | sed 's/^/kc: /'
      DIE "Keycloak container exited during startup"
    fi
    if curl -sS -f -m 5 -o /dev/null "$KC_REALM_URL/.well-known/openid-configuration" 2>/dev/null; then
      PASS "Keycloak realm kk is serving discovery after ~${i}s"
      return 0
    fi
    sleep 1
  done
  "$PODMAN" logs --tail 30 "$KC_NAME" 2>&1 | sed 's/^/kc: /'
  DIE "Keycloak did not serve realm kk within 120s"
}

# kc_admin_token prints an admin-cli access token for the master realm.
kc_admin_token() {
  curl -sS -m 20 "$KC_BASE/realms/master/protocol/openid-connect/token" \
    -d grant_type=password -d client_id=admin-cli -d username=admin \
    --data-urlencode "password=$KC_ADMIN_PASS" | jq -r '.access_token // empty'
}

# --- hub --------------------------------------------------------------------

build_hub() {
  STEP "build hub"
  mkdir -p "$HUB_DIR/data"
  if (cd "$REPO_ROOT" && go build -o "$WORK/kryptkeeper" ./cmd/kryptkeeper); then
    PASS "hub built"
  else
    DIE "go build ./cmd/kryptkeeper failed"
  fi
}

# start_hub [VAR=value ...] (re)starts the hub on a persistent data dir, so
# provisioned users survive a restart with different SSO settings. Extra
# arguments are env assignments for the hub process only.
start_hub() {
  stop_hub
  port_free "$HUB_PORT" || DIE "port $HUB_PORT is already in use (set KK_SSO_HUB_PORT)"
  env \
    APP_BOOTSTRAP_TOKEN="$(openssl rand -hex 16)" AUTH_MODE=bootstrap APP_CERTIFICATE_PROVIDER=ca \
    APP_CREDENTIAL_STORE_PASSPHRASE='sso-cred-passphrase-32-bytes-long!!' \
    KRYPTKEEPER_KEYSTORE_PASSPHRASE='sso-keystore-passphrase-32-bytes!!' \
    KRYPTKEEPER_DATA_DIR="$HUB_DIR/data" APP_CA_FILE="$HUB_DIR/data/cas.json" \
    APP_TEMPLATE_FILE="$HUB_DIR/data/templates.json" APP_CERTIFICATE_FILE="$HUB_DIR/data/certificates.json" \
    APP_AUDIT_FILE="$HUB_DIR/data/audit.json" APP_CERTS_SUMMARY_FILE="$HUB_DIR/data/certs_summary.json" \
    KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true KRYPTKEEPER_CA_NAME="SSO Harness Root CA" \
    APP_BIND_ADDR=127.0.0.1 PORT="$HUB_PORT" KRYPTKEEPER_BASE_URL="$HUB_BASE" \
    KRYPTKEEPER_TLS_SELF_ISSUE=true KRYPTKEEPER_TLS_SANS="localhost,127.0.0.1" \
    APP_USER_PROVIDER=db \
    APP_AUTH_LOGIN_SIGNING_SECRET="$LOGIN_SIGNING_SECRET" APP_SCIM_TOKEN="$SCIM_TOKEN" \
    APP_OIDC_LOGIN_ENABLED=true APP_OIDC_ISSUER="$KC_REALM_URL" APP_OIDC_AUDIENCE=lab-hub \
    APP_OIDC_CLIENT_ID=lab-hub APP_OIDC_CLIENT_SECRET="$KC_CLIENT_SECRET" \
    APP_OIDC_DISCOVERY_URL="$KC_REALM_URL/.well-known/openid-configuration" \
    APP_OIDC_REDIRECT_URL="$HUB_BASE/api/v1/auth/oidc/callback" \
    APP_AUTH_ROLE_CLAIM=groups \
    APP_AUTH_ROLE_MAP_JSON='[{"claim_value":"kk-admins","role":"pki-admin"},{"claim_value":"kk-operators","role":"pki-operator"},{"claim_value":"kk-auditors","role":"auditor"}]' \
    "$@" \
    "$WORK/kryptkeeper" >>"$WORK/hub.log" 2>&1 &
  HUB_PID=$!
  local i
  # 120 s: a cold hub spends several seconds in migrations and CA bootstrap, and far more
  # when the runner is busy; the exported CA below needs the listener up, not a retry.
  for i in $(seq 1 240); do
    curl -sSk -o /dev/null "$HUB_BASE/healthz" 2>/dev/null && break
    kill -0 "$HUB_PID" 2>/dev/null || DIE "hub exited during startup, see hub.log tail below"
    sleep 0.5
  done
  curl -sSk -o /dev/null "$HUB_BASE/healthz" 2>/dev/null || DIE "hub not listening on $HUB_BASE after 120 s, see hub.log tail below"
  if [ ! -s "$CA_PEM" ]; then
    # Export the hub's self-issued CA once (unauthenticated EST cacerts,
    # PKCS#7-decoded), exactly as tests/live/protocols/run.sh does; the probe
    # above is the only unverified request this harness makes.
    curl -sSk --max-time 5 -o "$WORK/cacerts.b64" "$HUB_BASE/.well-known/est/cacerts" \
      && openssl base64 -d -A -in "$WORK/cacerts.b64" -out "$WORK/cacerts.p7" \
      && openssl pkcs7 -inform der -in "$WORK/cacerts.p7" -print_certs -out "$CA_PEM" \
      && [ -s "$CA_PEM" ] || DIE "could not export the hub CA via EST cacerts"
  fi
  local names="" kv
  for kv in "$@"; do names="$names ${kv%%=*}"; done # names only, never values
  if curl -sS --cacert "$CA_PEM" "$HUB_BASE/healthz" | grep -q '"status":"ok"'; then
    PASS "hub healthy over verified TLS (pid $HUB_PID${names:+; extra env:$names})"
  else
    DIE "hub did not become healthy"
  fi
}

# hub_get <path> [jar]: GET with the hub CA and, when given, a cookie jar.
hub_get() {
  local path="$1" jar="${2:-}"
  if [ -n "$jar" ]; then
    curl -sS --cacert "$CA_PEM" -b "$jar" "$HUB_BASE$path"
  else
    curl -sS --cacert "$CA_PEM" "$HUB_BASE$path"
  fi
}

# hub_status <url> <jar> prints the HTTP status of a GET (cookie jar updated).
hub_status() {
  curl -sS --cacert "$CA_PEM" -b "$2" -c "$2" -o "$WORK/last-body" -w '%{http_code}' "$1"
}

has_session_cookie() { grep -q 'kk_token' "$1" 2>/dev/null; }

whoami_role() { hub_get /api/v1/protected/whoami "$1" | jq -r '.role // empty'; }

# scim_post <path> <json>: prints "<status> <body-file>".
scim_post() {
  local code
  code="$(curl -sS --cacert "$CA_PEM" -o "$WORK/scim-body" -w '%{http_code}' \
    -H "Authorization: Bearer $SCIM_TOKEN" -H 'Content-Type: application/scim+json' \
    -X POST -d "$2" "$HUB_BASE$1")"
  echo "$code"
}

scim_patch() {
  curl -sS --cacert "$CA_PEM" -o "$WORK/scim-body" -w '%{http_code}' \
    -H "Authorization: Bearer $SCIM_TOKEN" -H 'Content-Type: application/scim+json' \
    -X PATCH -d "$2" "$HUB_BASE$1"
}

# --- users ------------------------------------------------------------------

# fixture_pw <user>: matches realm/kk-realm.json (throwaway test fixture).
fixture_pw() { echo "$1-fixture-pw"; }

# provision_user <name>: SCIM-create name@sso.test once; remembers the id.
provision_user() {
  local name="$1" code
  [ -s "$WORK/uid-$name" ] && return 0
  code="$(scim_post /scim/v2/Users "{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:User\"],\"userName\":\"$name@sso.test\",\"emails\":[{\"value\":\"$name@sso.test\",\"primary\":true}],\"active\":true}")"
  if [ "$code" = 201 ]; then
    jq -r .id "$WORK/scim-body" >"$WORK/uid-$name"
    PASS "SCIM created $name@sso.test (201)"
  else
    FAIL "SCIM create $name@sso.test returned $code, want 201"
    return 1
  fi
}

# ensure_users: idempotent provisioning of the four OIDC/SAML fixture users.
ensure_users() {
  local u
  for u in alice bob carol dave; do provision_user "$u"; done
}

# --- browser simulation -----------------------------------------------------

# Prints the value of the Location header (CR stripped) from a header dump.
location_of() { awk 'tolower($1)=="location:"{sub(/\r$/,""); print $2; exit}' "$1"; }

# kc_login <user> <pass>: the real OIDC authorization-code flow with curl as
# the browser. Prints the hub callback URL (carrying code and state). The
# hub-side cookie jar, which holds the login-flow binding cookie, is
# $WORK/jar-<user>-hub and must be reused when calling the callback.
kc_login() {
  local user="$1" pass="$2"
  local hubjar="$WORK/jar-$user-hub" kcjar="$WORK/jar-$user-kc"
  rm -f "$hubjar" "$kcjar"
  curl -sS --cacert "$CA_PEM" -c "$hubjar" -D "$WORK/h1" -o /dev/null "$HUB_BASE/api/v1/auth/oidc/login" || return 1
  local authurl form action
  authurl="$(location_of "$WORK/h1")"
  [ -n "$authurl" ] || { echo "no Location from /oidc/login" >&2; return 1; }
  # The login form's action embeds per-request session codes; never hard-code it.
  form="$(curl -sS -L -c "$kcjar" -b "$kcjar" "$authurl")" || return 1
  action="$(printf '%s' "$form" | grep -o 'action="[^"]*"' | head -1 | sed 's/^action="//; s/"$//; s/&amp;/\&/g')"
  [ -n "$action" ] || { echo "no login form action found" >&2; return 1; }
  curl -sS -c "$kcjar" -b "$kcjar" -D "$WORK/h2" -o /dev/null \
    --data-urlencode "username=$user" --data-urlencode "password=$pass" --data-urlencode "credentialId=" \
    "$action" || return 1
  location_of "$WORK/h2"
}

# callback_status <user> <callback-url>: GET it with the user's hub jar and
# print the HTTP status; the session cookie (if any) lands in the same jar.
callback_status() { hub_status "$2" "$WORK/jar-$1-hub"; }

# --- Keycloak admin (W22-22) ------------------------------------------------

# kc_partial_import <file>: POST a partial-import body to realm kk.
kc_partial_import() {
  local token code
  token="$(kc_admin_token)"
  [ -n "$token" ] || { echo "no Keycloak admin token" >&2; return 1; }
  code="$(curl -sS -o "$WORK/kc-import.out" -w '%{http_code}' \
    -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
    -X POST --data-binary "@$1" "$KC_BASE/admin/realms/kk/partialImport")"
  [ "$code" = 200 ] || { echo "partialImport returned $code: $(head -c 300 "$WORK/kc-import.out")" >&2; return 1; }
}

# ensure_saml_fixtures: import the SAML clients and erin once per run.
ensure_saml_fixtures() {
  [ -f "$WORK/saml-fixtures-done" ] && return 0
  if kc_partial_import "$HERE/realm/saml-clients.json"; then
    : >"$WORK/saml-fixtures-done"
    PASS "Keycloak partial import: SAML clients kk-saml-sp, kk-saml-other and user erin ($(jq -c '{added,skipped,overwritten}' "$WORK/kc-import.out"))"
  else
    FAIL "Keycloak partial import of realm/saml-clients.json failed"
    return 1
  fi
}

# configure_hub_saml [VAR=value ...]: restart the hub with SAML login enabled
# against realm kk. The IdP signing certificate comes from the realm's SAML
# descriptor (X509Certificate, wrapped as PEM).
configure_hub_saml() {
  local b64 pem
  b64="$(curl -sS "$KC_REALM_URL/protocol/saml/descriptor" | tr -d '\n' | grep -o '<ds:X509Certificate>[^<]*</ds:X509Certificate>' | head -1 | sed 's/<[^>]*>//g')"
  [ -n "$b64" ] || DIE "could not read the realm SAML signing certificate"
  pem="$(printf -- '-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n' "$(printf '%s' "$b64" | fold -w 64)")"
  printf '%s' "$pem" | openssl x509 -noout >/dev/null 2>&1 || DIE "realm SAML signing certificate does not parse"
  start_hub \
    APP_SAML_LOGIN_ENABLED=true APP_SAML_IDP_SSO_URL="$KC_REALM_URL/protocol/saml" \
    APP_SAML_IDP_ISSUER="$KC_REALM_URL" APP_SAML_SP_ISSUER=kk-saml-sp APP_SAML_AUDIENCE=kk-saml-sp \
    APP_SAML_ACS_URL="$HUB_BASE/api/v1/auth/saml/acs" APP_SAML_IDP_CERTIFICATE="$pem" "$@"
}

# html_attr <html-file> <input-name>: value of a hidden form input, with the
# HTML entities Keycloak applies (&#x3d; &amp; ...) undone exactly once.
html_attr() {
  grep -io "name=\"$2\" value=\"[^\"]*\"" "$1" | head -1 | sed -E 's/^[^=]*="[^"]*" value="//; s/"$//' \
    | python3 -I -c 'import html,sys; sys.stdout.write(html.unescape(sys.stdin.read().rstrip("\n")))'
}

# saml_extract <html-file> <tag>: save the auto-post form's SAMLResponse and
# RelayState under $WORK/saml-<tag>.{resp,relay}. Returns 1 if there is none.
saml_extract() {
  html_attr "$1" SAMLResponse >"$WORK/saml-$2.resp"
  html_attr "$1" RelayState >"$WORK/saml-$2.relay"
  [ -s "$WORK/saml-$2.resp" ]
}

# saml_login <user> <pass> <tag>: SP-initiated SAML login through Keycloak,
# stopping at the auto-post form. Reuses the user's Keycloak session when one
# exists. Leaves the response in $WORK/saml-<tag>.resp, not yet posted.
saml_login() {
  local user="$1" pass="$2" tag="$3"
  local hubjar="$WORK/jar-saml-$user-hub" kcjar="$WORK/jar-saml-$user-kc" authurl action
  rm -f "$hubjar"
  curl -sS --cacert "$CA_PEM" -c "$hubjar" -D "$WORK/sh1" -o /dev/null "$HUB_BASE/api/v1/auth/saml/login" || return 1
  authurl="$(location_of "$WORK/sh1")"
  [ -n "$authurl" ] || { echo "no Location from /saml/login" >&2; return 1; }
  curl -sS -L -c "$kcjar" -b "$kcjar" -o "$WORK/sh2.html" "$authurl" || return 1
  if ! saml_extract "$WORK/sh2.html" "$tag"; then
    action="$(grep -o 'action="[^"]*"' "$WORK/sh2.html" | head -1 | sed 's/^action="//; s/"$//; s/&amp;/\&/g')"
    [ -n "$action" ] || { echo "no login form action found" >&2; return 1; }
    curl -sS -c "$kcjar" -b "$kcjar" -o "$WORK/sh3.html" \
      --data-urlencode "username=$user" --data-urlencode "password=$pass" --data-urlencode "credentialId=" "$action" || return 1
    saml_extract "$WORK/sh3.html" "$tag" || { echo "Keycloak returned no SAMLResponse form" >&2; return 1; }
  fi
}

# saml_idp_initiated <user> <client-url-name> <tag>: with the user's existing
# Keycloak session, fetch an unsolicited (IdP-initiated) response.
saml_idp_initiated() {
  curl -sS -L -b "$WORK/jar-saml-$1-kc" -c "$WORK/jar-saml-$1-kc" -o "$WORK/sh4.html" "$KC_REALM_URL/protocol/saml/clients/$2" || return 1
  saml_extract "$WORK/sh4.html" "$3"
}

# saml_acs_post <user> <tag>: POST the saved response to the hub ACS with the
# user's hub jar; prints the HTTP status. A session cookie lands in the jar.
saml_acs_post() {
  local args=(--data-urlencode "SAMLResponse@$WORK/saml-$2.resp")
  [ -s "$WORK/saml-$2.relay" ] && args+=(--data-urlencode "RelayState@$WORK/saml-$2.relay")
  curl -sS --cacert "$CA_PEM" -b "$WORK/jar-saml-$1-hub" -c "$WORK/jar-saml-$1-hub" \
    -o "$WORK/last-body" -w '%{http_code}' "${args[@]}" "$HUB_BASE/api/v1/auth/saml/acs"
}
