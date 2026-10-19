#!/usr/bin/env bash
# W29-01: drive a REAL hub process (Workload API on a Unix socket) with the
# real go-spiffe workloadapi client. Two phases: the signing CA id is only
# known after the CA exists, and SPIFFE_SIGNING_CA_ID is read at listener
# start, so the hub is started once to create the CA and restarted on the
# same data dir with the SPIFFE env.
set -u
set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
WORK="$(mktemp -d /tmp/kk-uat-spiffe.XXXXXX)"   # short path: macOS sun_path ~104 bytes
SOCK="$WORK/w.sock"
TOKEN=uat-token
TTL=20s
TRUST_DOMAIN=kk.test

FAILED=0
STEP() { echo; echo "== $* =="; }
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }
HUB_PID=""
stop_hub() { [ -n "$HUB_PID" ] && kill "$HUB_PID" 2>/dev/null && wait "$HUB_PID" 2>/dev/null; HUB_PID=""; }
cleanup() { stop_hub; rm -rf "$WORK"; }
trap cleanup EXIT
DIE() { echo "FAIL: $*"; [ -f "$WORK/hub.log" ] && tail -20 "$WORK/hub.log"; exit 1; }

free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
HUB_PORT="$(free_port)"
HUB_BASE="http://127.0.0.1:${HUB_PORT}"

api() { curl -sS -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' "$@"; }
jget() { python3 -c 'import json,sys
d=json.load(sys.stdin)
for k in sys.argv[1].split("."):
    d=d[int(k)] if isinstance(d,list) else d[k]
print(d)' "$1" 2>/dev/null; }

# Named administrators are provisioned through APP_API_KEYS_JSON (config-loaded
# keys have no minter). Keys minted with the bootstrap token are setup
# credentials and can never approve an NHI, so the proposer and approver the
# W29-05 tests need must come from here.
PEPPER='uat-spiffe-pepper-32chars-minimum!'
KEYS_JSON=""
mkkey() { # name -> sets KK_SPIFFE_<NAME>_TOKEN and appends to KEYS_JSON
  local name="$1" secret verifier up
  secret="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  verifier="$(printf '%s' "$secret" | openssl dgst -sha256 -hmac "$PEPPER" -hex | awk '{print $NF}')"
  KEYS_JSON="${KEYS_JSON:+$KEYS_JSON,}{\"name\":\"$name\",\"kid\":\"uat$name\",\"secret_verifier\":\"$verifier\",\"principal_id\":\"$name\",\"role\":\"pki-admin\",\"active\":true}"
  up="$(echo "$name" | tr '[:lower:]' '[:upper:]')"
  export "KK_SPIFFE_${up}_TOKEN=kk_uat${name}_${secret}"
}
mkkey proposer; mkkey approver

hub_env() {
  export APP_BOOTSTRAP_TOKEN="$TOKEN" AUTH_MODE=bootstrap APP_CERTIFICATE_PROVIDER=ca \
    KRYPTKEEPER_TLS_DISABLE=true APP_NOTIFICATION_PROVIDER=file \
    APP_CREDENTIAL_STORE_PASSPHRASE='uat-spiffe-cred-passphrase-32-b' \
    KRYPTKEEPER_KEYSTORE_PASSPHRASE='uat-spiffe-keystore-passphrase-32' \
    KRYPTKEEPER_DATA_DIR="$WORK/data" \
    APP_CA_FILE="$WORK/data/cas.json" \
    APP_TEMPLATE_FILE="$WORK/data/templates.json" \
    APP_CERTIFICATE_FILE="$WORK/data/certificates.json" \
    APP_AUDIT_FILE="$WORK/data/audit.json" \
    APP_CERTS_SUMMARY_FILE="$WORK/data/certs_summary.json" \
    APP_API_KEY_PEPPER="$PEPPER" APP_API_KEY_AUTH_ENABLED=true APP_API_KEYS_JSON="[$KEYS_JSON]" \
    KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true KRYPTKEEPER_CA_NAME="UAT Root CA" \
    APP_BIND_ADDR=127.0.0.1 PORT="$HUB_PORT"
}

start_hub() {
  "$WORK/kryptkeeper" >>"$WORK/hub.log" 2>&1 &
  HUB_PID=$!
  local tries=40
  until curl -s -f -o /dev/null "${HUB_BASE}/api/v1/cas" -H "Authorization: Bearer ${TOKEN}"; do
    tries=$((tries - 1)); [ $tries -le 0 ] && DIE "hub never answered, see $WORK/hub.log"
    sleep 1
  done
}

STEP "build hub"
mkdir -p "$WORK/data"
( cd "$REPO_ROOT" && go build -o "$WORK/kryptkeeper" ./cmd/kryptkeeper ) && PASS "hub built" || DIE "go build failed"

STEP "phase 1: create the signing CA"
hub_env
start_hub
CA_ID="$(api -X POST "$HUB_BASE/api/v1/cas" -d '{"name":"spiffe-root","type":"root","algorithm":"ECDSA-P256","subject_cn":"Spiffe Root"}' | jget data.id)"
[ -n "$CA_ID" ] && PASS "CA created ($CA_ID)" || DIE "CA create failed, see $WORK/hub.log"
stop_hub

STEP "phase 2: restart with the Workload API socket"
export SPIFFE_TRUST_DOMAIN="$TRUST_DOMAIN" SPIFFE_SIGNING_CA_ID="$CA_ID" SPIFFE_SVID_TTL="$TTL" SPIFFE_WORKLOAD_SOCKET="$SOCK"
start_hub
for _ in $(seq 1 20); do [ -S "$SOCK" ] && break; sleep 0.5; done
[ -S "$SOCK" ] && PASS "workload socket up at $SOCK" || DIE "socket never appeared, see $WORK/hub.log"

STEP "go-spiffe live tests"
export KK_LIVE_SPIFFE=1 KK_SPIFFE_HUB_BASE="$HUB_BASE" KK_SPIFFE_TOKEN="$TOKEN" \
  KK_SPIFFE_SOCKET="$SOCK" KK_SPIFFE_TRUST_DOMAIN="$TRUST_DOMAIN" KK_SPIFFE_TTL="$TTL"
( cd "$REPO_ROOT" && go test ./tests/live/spiffe/... -count=1 -v -timeout 10m ) 2>&1 | tee "$WORK/test.log"
[ "${PIPESTATUS[0]}" -eq 0 ] || FAILED=1

STEP "summary"
grep -E -- '^--- (PASS|FAIL|SKIP): ' "$WORK/test.log" | while read -r _ verdict name _; do
  case "$verdict" in PASS:) echo "PASS: $name" ;; *) echo "FAIL: $name ($verdict)" ;; esac
done
NPASS="$(grep -c -- '^--- PASS: ' "$WORK/test.log")"
NOTPASS="$(grep -c -E -- '^--- (FAIL|SKIP): ' "$WORK/test.log")"
echo "$NPASS passed, $NOTPASS failed/skipped"
[ "$NPASS" -eq 10 ] && [ "$NOTPASS" -eq 0 ] || FAILED=1
[ $FAILED -eq 0 ] && { echo "ALL PASS"; exit 0; }
echo "hub log tail:"; tail -20 "$WORK/hub.log"
exit 1
