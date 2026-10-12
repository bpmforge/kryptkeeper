#!/usr/bin/env bash
# W19-14: prove the hub actually serves TLS (previously it had no TLS
# listener at all -- UAT W19-05) and that EST, which RFC 7030 mandates TLS
# for, works end to end against it: cacerts, enroll, reenroll, all via the
# real github.com/globalsign/est client library.
#
# A separate script from tests/live/protocols/run.sh on purpose: that
# fixture is owned by ticket W19-05 (docs lane) per docs/board/plan.json,
# and this ticket's notes say to re-run it there for the live proof rather
# than editing it here -- this script reuses its estcheck/ harness (which
# W19-14 extended with real chain verification) and est-run.sh unchanged.
#
# Idempotent, PASS/FAIL per step, non-zero exit on any FAIL, cleans up its
# own hub process/container/state on exit (trap). No real key material is
# ever committed: every key is generated fresh into a temp dir per run, and
# the hub's self-issued listener/CA keys live only under $WORK.
#
# Podman only (no docker); the container reaches the host hub at
# host.containers.internal:$HUB_PORT.
set -u
set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$(dirname "${BASH_SOURCE[0]}")/../podman-host.sh"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
PROTOCOLS_DIR="$REPO_ROOT/tests/live/protocols"
WORK="$(mktemp -d /tmp/kk-uat-tls.XXXXXX)"
HUB_DIR="$WORK/hub"
HUB_PORT="${HUB_PORT:-8097}"
HUB_BASE="https://127.0.0.1:${HUB_PORT}"
TOKEN=uat-tls-token
GOLANG_IMG=docker.io/library/golang:1.23-alpine

FAILED=0
STEP() { echo; echo "== $* =="; }
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }
DIE()  { echo "FAIL: $*"; cleanup; exit 1; }

HUB_PID=""
cleanup() {
  STEP "cleanup"
  [ -n "$HUB_PID" ] && kill "$HUB_PID" >/dev/null 2>&1 || true
  [ -n "$HUB_PID" ] && wait "$HUB_PID" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 1. Build and start the hub with KRYPTKEEPER_TLS_SELF_ISSUE=true.
# ---------------------------------------------------------------------------
STEP "build hub"
mkdir -p "$HUB_DIR/data"
(cd "$REPO_ROOT" && go build -o "$WORK/kryptkeeper" ./cmd/kryptkeeper) \
  && PASS "hub built" || DIE "go build ./cmd/kryptkeeper failed"

STEP "start hub on :$HUB_PORT (TLS self-issued from the hub's own CA)"
export APP_BOOTSTRAP_TOKEN="$TOKEN" AUTH_MODE=bootstrap APP_CERTIFICATE_PROVIDER=ca \
  APP_DISCOVERY_PROVIDER=db APP_NOTIFICATION_PROVIDER=file
export APP_CREDENTIAL_STORE_PASSPHRASE='uat-tls-cred-passphrase-32-bytes!!' \
  KRYPTKEEPER_KEYSTORE_PASSPHRASE='uat-tls-keystore-passphrase-32-byte!!'
export KRYPTKEEPER_DATA_DIR="$HUB_DIR/data"
export KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true KRYPTKEEPER_CA_NAME="UAT TLS Root CA"
export APP_BIND_ADDR=0.0.0.0 PORT="$HUB_PORT"
export KRYPTKEEPER_BASE_URL="https://host.containers.internal:${HUB_PORT}"
export KRYPTKEEPER_TLS_SELF_ISSUE=true
# EST needs a credential (W20-14, D-112): the estcheck client enrolls with
# HTTP Basic from the test users fixture, then re-enrolls with the TLS client
# certificate it just received, which needs client-certificate requests.
export KRYPTKEEPER_EST_USERS_FILE="$(cd "$(dirname "$0")" && pwd)/../protocols/est-users.json"
export KRYPTKEEPER_TLS_REQUEST_CLIENT_CERT=true
export KRYPTKEEPER_TLS_SANS="localhost,127.0.0.1,host.containers.internal"

"$WORK/kryptkeeper" >"$WORK/hub.log" 2>&1 &
HUB_PID=$!
for _ in $(seq 1 30); do
  curl -sSk -o /dev/null "$HUB_BASE/healthz" && break
  sleep 0.5
done
curl -sSk "$HUB_BASE/healthz" | grep -q '"status":"ok"' \
  && PASS "hub healthy over TLS (pid $HUB_PID, insecure curl -- socket speaks TLS at all)" \
  || DIE "hub did not come up, see $WORK/hub.log"

# ---------------------------------------------------------------------------
# 2. Fetch the hub's own CA cert via EST cacerts (unauthenticated per RFC
#    7030) and verify readyz/healthz against it with a REAL chain -- no -k,
#    no --insecure, an actual TLS handshake against a cert this CA issued.
# ---------------------------------------------------------------------------
STEP "TLS: real chain verification against the hub's self-issued CA"
curl -sSk --max-time 3 -o "$WORK/cacerts.b64" "$HUB_BASE/.well-known/est/cacerts" \
  && openssl base64 -d -A -in "$WORK/cacerts.b64" -out "$WORK/cacerts.p7" \
  && openssl pkcs7 -inform der -in "$WORK/cacerts.p7" -print_certs -out "$WORK/ca.pem" \
  && PASS "fetched+decoded the hub's CA cert from EST cacerts (real PKCS#7, not raw DER)" \
  || DIE "could not fetch/decode the hub's CA cert via EST cacerts"

if curl -sS --max-time 3 --cacert "$WORK/ca.pem" "$HUB_BASE/healthz" | grep -q '"status":"ok"'; then
  PASS "healthz verifies against the hub's own CA (real chain, no bypass)"
else
  FAIL "healthz did not verify against the hub's own CA"
fi
if curl -sS --max-time 3 --cacert "$WORK/ca.pem" "$HUB_BASE/readyz" | grep -q '"status":"ready"'; then
  PASS "readyz verifies against the hub's own CA (real chain, no bypass)"
else
  FAIL "readyz did not verify against the hub's own CA"
fi

# ---------------------------------------------------------------------------
# 3. EST -- real client: github.com/globalsign/est (RFC 7030 mandates TLS,
#    which the hub previously had none of at all -- UAT W19-05). Reuses
#    tests/live/protocols/estcheck (W19-14 added a real ExplicitAnchor chain
#    verification pass there) and est-run.sh unchanged.
# ---------------------------------------------------------------------------
STEP "EST: real client (globalsign/est) against https://.../.well-known/est/ -- cacerts, enroll, reenroll"
podman run ${KK_PODMAN_HOST_ARGS} --rm \
  -v "$PROTOCOLS_DIR/estcheck:/src:ro" -v "$PROTOCOLS_DIR/est-run.sh:/est-run.sh:ro" \
  -e EST_HOST="host.containers.internal:${HUB_PORT}" -e EST_USER=uat-est -e EST_PASS=uat-est-password \
  "$GOLANG_IMG" sh /est-run.sh >"$WORK/est.log" 2>&1
cat "$WORK/est.log"
if grep -q "PASS bootstrap cacerts" "$WORK/est.log"; then
  PASS "EST cacerts (bootstrap trust anchor) via globalsign/est"
else
  FAIL "EST cacerts (bootstrap): real client cannot complete (see $WORK/est.log)"
fi
if grep -q "^PASS cacerts:" "$WORK/est.log"; then
  PASS "EST cacerts (verified against ExplicitAnchor) via globalsign/est"
else
  FAIL "EST cacerts (verified): real client cannot complete (see $WORK/est.log)"
fi
if grep -q "PASS enroll" "$WORK/est.log"; then
  PASS "EST enroll via globalsign/est"
else
  FAIL "EST enroll: real client cannot complete (see $WORK/est.log)"
fi
if grep -q "PASS reenroll" "$WORK/est.log"; then
  PASS "EST reenroll via globalsign/est"
else
  FAIL "EST reenroll: real client cannot complete (see $WORK/est.log)"
fi

# ---------------------------------------------------------------------------
STEP "summary"
if [ "$FAILED" -eq 0 ]; then
  echo "ALL STEPS PASSED"
else
  echo "ONE OR MORE STEPS FAILED -- see FAIL lines above"
fi
exit "$FAILED"
