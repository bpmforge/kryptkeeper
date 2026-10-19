#!/usr/bin/env bash
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../../lib/podman.sh"
set -uo pipefail

# filename: tests/live/protocols/policy-refusal/run.sh
#
# W22-17: prove that an issuance-policy refusal reaches REAL protocol clients
# with the rule text, and that nothing is signed. A restrictive policy
# ("rsa-only": allowed_algorithms = [RSA-3072, RSA-4096]; since W23-54 the
# engine names RSA keys by size, so RSA-3072 must be listed explicitly) is created through the real admin API (W22-14); then
#   - lego (ACME) asks for a P-256 certificate  -> refused, rule in the problem
#   - globalsign/est (estcheck) enrolls a P-256 key -> refused, rule in the body
# with positive controls (RSA-3072 ACME order succeeds; EST enroll succeeds
# before the policy exists) proving the policy is not a blanket block.
# The spec's P-384 allow-list could not be used: lego also uses --key-type for
# its ACCOUNT key and the hub's ACME rejects P-384 account JWKs.
#
# Self-contained (own podman network and hub, same shape as tests/live/acme):
# ACME http-01 needs the hub to dial the client container on :80, which the
# host-process hub in tests/live/protocols/run.sh cannot do. Exits non-zero on
# any FAIL, and explicitly FAILs if a refused flow produced a certificate.

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$HERE/../../../.." && pwd)"
RUN_DIR="${KK_UAT_RUN_DIR:-$HOME/kk-uat-policy-run}"   # under $HOME: podman machine on macOS only virtiofs-mounts /Users
NETWORK="kk-uat-policy"
HUB_NAME="kk-pol-hub"
HUB_HOST="kk-pol-hub"
HUB_PORT="8080"
HUB_BASE="https://$HUB_HOST:$HUB_PORT"
ACME_SERVER="$HUB_BASE/acme/directory"
BOOTSTRAP_TOKEN="uat-token"
GOLANG_IMG=docker.io/library/golang:1.23-alpine
GOARCH_HUB="${KK_UAT_GOARCH:-$(kk_goarch)}"   # must match the podman machine

PASS=0
FAIL=0
pass() { echo "PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL+1)); }

curl_hub() {
  # Inside the network, verifying against the hub's own exported CA -- never -k.
  podman run --rm --network "$NETWORK" -v "$RUN_DIR/tls-export:/caexport:ro" \
    curlimages/curl:8.10.1 --cacert /caexport/ca.pem "$@"
}
api() { curl_hub -sS -H "Authorization: Bearer $BOOTSTRAP_TOKEN" "$@"; }

# count_source SOURCE: how many inventory certificates carry that source.
count_source() {
  api "$HUB_BASE/api/v1/certificates?limit=200" | python3 -c "
import json,sys
d=json.load(sys.stdin)
certs=d.get('data', d.get('certificates', []))
print(sum(1 for c in certs if c.get('source') == '$1'))" 2>/dev/null || echo -1
}

cleanup() {
  # One name per call: podman 4.9 rm -f silently removes nothing when any listed name is already gone.
  kk_rm kk-pol-lego-ok kk-pol-lego-bad "$HUB_NAME"
  podman network rm "$NETWORK" >/dev/null 2>&1 || true
}

echo "=== W22-17 policy-refusal live proof: setup ==="
cleanup
trap cleanup EXIT INT TERM
rm -rf "$RUN_DIR"
mkdir -p "$RUN_DIR/bin" "$RUN_DIR/data" "$RUN_DIR/lego" "$RUN_DIR/tls-export"

for img in docker.io/goacme/lego:latest curlimages/curl:8.10.1 alpine:3 "$GOLANG_IMG"; do
  podman pull -q "$img" >/dev/null 2>&1 || true
done

if ! (cd "$ROOT_DIR" && GOOS=linux GOARCH="$GOARCH_HUB" CGO_ENABLED=0 go build -o "$RUN_DIR/bin/kryptkeeper" ./cmd/kryptkeeper); then
  fail "build hub binary"
  echo "=== RESULT: $PASS passed, $FAIL failed ==="
  exit 1
fi
pass "build hub binary"

podman network create "$NETWORK" >/dev/null
pass "create podman network $NETWORK"

# The EST credential (W20-14) and client-certificate requests for re-enroll,
# same fixture as tests/live/protocols/run.sh.
podman run -d --name "$HUB_NAME" --network "$NETWORK" --hostname "$HUB_HOST" \
  -v "$RUN_DIR/bin/kryptkeeper:/kryptkeeper:ro" \
  -v "$RUN_DIR/data:/data" \
  -v "$RUN_DIR/tls-export:/tls-export" \
  -v "$HERE/../est-users.json:/est-users.json:ro" \
  -e APP_BOOTSTRAP_TOKEN="$BOOTSTRAP_TOKEN" -e AUTH_MODE=bootstrap \
  -e APP_CERTIFICATE_PROVIDER=ca -e APP_DISCOVERY_PROVIDER=db -e APP_NOTIFICATION_PROVIDER=file \
  -e KRYPTKEEPER_TLS_SELF_ISSUE=true -e KRYPTKEEPER_TLS_SANS="$HUB_HOST" \
  -e KRYPTKEEPER_TLS_TRUST_EXPORT_DIR=/tls-export \
  -e KRYPTKEEPER_TLS_REQUEST_CLIENT_CERT=true -e KRYPTKEEPER_EST_USERS_FILE=/est-users.json \
  -e APP_CREDENTIAL_STORE_PASSPHRASE='uat-cred-passphrase-32-bytes-long!!' \
  -e KRYPTKEEPER_KEYSTORE_PASSPHRASE='uat-keystore-passphrase-32-bytes!!' \
  -e KRYPTKEEPER_DATA_DIR=/data \
  -e APP_CA_FILE=/data/cas.json -e APP_TEMPLATE_FILE=/data/templates.json \
  -e APP_CERTIFICATE_FILE=/data/certificates.json -e APP_AUDIT_FILE=/data/audit.json \
  -e APP_CERTS_SUMMARY_FILE=/data/certs_summary.json \
  -e KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true -e KRYPTKEEPER_CA_NAME="UAT Root CA" \
  -e APP_BIND_ADDR="$HUB_HOST" -e PORT="$HUB_PORT" \
  -e KRYPTKEEPER_BASE_URL="$HUB_BASE" \
  alpine:3 /kryptkeeper >/dev/null

for _ in $(seq 1 20); do
  podman logs "$HUB_NAME" 2>&1 | grep -q "starting kryptkeeper on $HUB_HOST:$HUB_PORT" && break
  sleep 1
done
if ! podman logs "$HUB_NAME" 2>&1 | grep -q "starting kryptkeeper on $HUB_HOST:$HUB_PORT"; then
  fail "hub startup (see: podman logs $HUB_NAME)"
  podman logs "$HUB_NAME" 2>&1 | tail -40
  echo "=== RESULT: $PASS passed, $FAIL failed ==="
  exit 1
fi
pass "hub startup"

for _ in $(seq 1 15); do
  [[ -s "$RUN_DIR/tls-export/ca.pem" ]] && break
  sleep 1
done
if [[ -s "$RUN_DIR/tls-export/ca.pem" ]]; then
  pass "hub exported its self-issued listener CA"
else
  fail "hub exported its self-issued listener CA"
  podman logs "$HUB_NAME" 2>&1 | tail -40
  echo "=== RESULT: $PASS passed, $FAIL failed ==="
  exit 1
fi

# ---------------------------------------------------------------------------
# EST helper: one estcheck run (enroll + reenroll) on the network.
# ---------------------------------------------------------------------------
run_estcheck() {
  podman run --rm --network "$NETWORK" \
    -v "$HERE/../estcheck:/src:ro" -v "$HERE/../est-run.sh:/est-run.sh:ro" \
    -e EST_HOST="$HUB_HOST:$HUB_PORT" -e EST_USER=uat-est -e EST_PASS=uat-est-password \
    "$GOLANG_IMG" sh /est-run.sh 2>&1
}

echo "=== EST positive control (before any restrictive policy) ==="
EST_OK_OUT="$(run_estcheck)"; EST_OK_RC=$?
echo "$EST_OK_OUT" | tail -8
if [[ $EST_OK_RC -eq 0 ]] && echo "$EST_OK_OUT" | grep -q "PASS enroll"; then
  pass "EST control: enroll succeeds under the baseline policy alone"
else
  fail "EST control: enroll succeeds under the baseline policy alone"
fi
EST_BEFORE="$(count_source est)"
if [[ "$EST_BEFORE" -ge 1 ]]; then
  pass "EST control: inventory holds $EST_BEFORE source=est certificate(s)"
else
  fail "EST control: expected source=est certificates in inventory, got $EST_BEFORE"
fi

# ---------------------------------------------------------------------------
# 3. Create the restrictive policy through the real admin API.
# ---------------------------------------------------------------------------
echo "=== create restrictive policy via POST /api/v1/policies ==="
POL_CODE="$(api -o /dev/null -w '%{http_code}' -X POST "$HUB_BASE/api/v1/policies" \
  -H 'Content-Type: application/json' \
  -d '{"name":"rsa-only","enabled":true,"rules":{"allowed_algorithms":["RSA-3072","RSA-4096"]}}')"
if [[ "$POL_CODE" == "201" ]]; then
  pass "policy rsa-only created (201)"
else
  fail "policy rsa-only created (got HTTP $POL_CODE)"
  echo "=== RESULT: $PASS passed, $FAIL failed ==="
  exit 1
fi

LEGO_COMMON=(--accept-tos --email uat@example.test --server "$ACME_SERVER" --path /data)
LEGO_ENV=(-e LEGO_CA_CERTIFICATES=/etc/kk-ca/ca.pem -v "$RUN_DIR/tls-export/ca.pem:/etc/kk-ca/ca.pem:ro")
# lego 5.x flattened CLI; image is distroless, so flags go straight to the binary.
run_lego() { # name key-type
  kk_wait_dns "$NETWORK" "$HUB_HOST" || { fail "dns: $HUB_HOST did not resolve on $NETWORK (podman DNS blackout after a container removal), so the next step cannot be trusted"; return 1; }
  podman run --name "$1" --network "$NETWORK" --hostname "$1" \
    -v "$RUN_DIR/lego:/data" "${LEGO_ENV[@]}" \
    docker.io/goacme/lego:latest \
    run "${LEGO_COMMON[@]}" --key-type "$2" --domains "$1" --http --http.address :80 2>&1
}

echo "=== ACME positive control (an RSA-3072 key is on the allow-list) ==="
ACME_OK_OUT="$(run_lego kk-pol-lego-ok rsa3072)"; ACME_OK_RC=$?
kk_rm kk-pol-lego-ok
echo "$ACME_OK_OUT" | tail -5
if [[ $ACME_OK_RC -eq 0 && -s "$RUN_DIR/lego/certificates/kk-pol-lego-ok.crt" ]]; then
  pass "ACME control: lego obtains an RSA-3072 certificate"
else
  fail "ACME control: lego obtains an RSA-3072 certificate (rc=$ACME_OK_RC)"
fi
ACME_BEFORE="$(count_source acme)"
if [[ "$ACME_BEFORE" == "1" ]]; then
  pass "ACME control: exactly 1 source=acme certificate in inventory"
else
  fail "ACME control: expected 1 source=acme certificate, got $ACME_BEFORE"
fi

echo "=== ACME refusal (an ECDSA P-256 key violates allowed_algorithms) ==="
ACME_BAD_OUT="$(run_lego kk-pol-lego-bad ec256)"; ACME_BAD_RC=$?
kk_rm kk-pol-lego-bad
echo "$ACME_BAD_OUT" | tail -8
if [[ $ACME_BAD_RC -ne 0 ]]; then
  pass "ACME refusal: lego exits non-zero"
else
  fail "ACME refusal: lego exited 0 for a policy-violating order"
fi
if echo "$ACME_BAD_OUT" | grep -qE 'allowed_algorithms|rsa-only'; then
  pass "ACME refusal: client output cites the rule"
else
  fail "ACME refusal: client output does not cite allowed_algorithms/rsa-only"
fi
if [[ -e "$RUN_DIR/lego/certificates/kk-pol-lego-bad.crt" ]]; then
  fail "ACME refusal: a certificate file was written for the refused order"
else
  pass "ACME refusal: no certificate file written"
fi
ACME_AFTER="$(count_source acme)"
if [[ "$ACME_AFTER" == "$ACME_BEFORE" ]]; then
  pass "ACME refusal: nothing signed (source=acme count still $ACME_AFTER)"
else
  fail "ACME refusal: SIGNED A CERTIFICATE (source=acme $ACME_BEFORE -> $ACME_AFTER)"
fi

echo "=== EST refusal (P-256 enroll violates allowed_algorithms) ==="
EST_BAD_OUT="$(run_estcheck)"; EST_BAD_RC=$?
echo "$EST_BAD_OUT" | tail -8
if [[ $EST_BAD_RC -ne 0 ]] && echo "$EST_BAD_OUT" | grep -q "FAIL enroll" && ! echo "$EST_BAD_OUT" | grep -q "PASS enroll"; then
  pass "EST refusal: enroll step fails"
else
  fail "EST refusal: enroll step did not fail (rc=$EST_BAD_RC)"
fi
if echo "$EST_BAD_OUT" | grep -qE 'allowed_algorithms|rsa-only'; then
  pass "EST refusal: client error cites the rule"
else
  fail "EST refusal: client error does not cite allowed_algorithms/rsa-only"
fi
EST_AFTER="$(count_source est)"
if [[ "$EST_AFTER" == "$EST_BEFORE" ]]; then
  pass "EST refusal: nothing signed (source=est count still $EST_AFTER)"
else
  fail "EST refusal: SIGNED A CERTIFICATE (source=est $EST_BEFORE -> $EST_AFTER)"
fi

# ---------------------------------------------------------------------------
# 7. Mandatory fallbacks: hub log and audit trail, independent of what the
#    clients managed to print.
# ---------------------------------------------------------------------------
echo "=== hub log and audit trail ==="
HUB_LOG="$(podman logs "$HUB_NAME" 2>&1)"
# The hub logs JSON (slog, W30-11), so the quotes inside msg arrive as \".
POLICY_LOG_TEXT='issuance policy \"rsa-only\"'
if echo "$HUB_LOG" | grep -E 'acme finalize' | grep -qF "$POLICY_LOG_TEXT"; then
  pass "hub log: ACME finalize refusal cites issuance policy \"rsa-only\""
else
  fail "hub log: no ACME finalize line citing issuance policy \"rsa-only\""
fi
if echo "$HUB_LOG" | grep -E 'est .*issuance failed' | grep -qF "$POLICY_LOG_TEXT"; then
  pass "hub log: EST enroll refusal cites issuance policy \"rsa-only\""
else
  fail "hub log: no EST enroll line citing issuance policy \"rsa-only\""
fi
AUDIT_BODY="$(api "$HUB_BASE/api/v1/audit?action=policy.violation&limit=50")"
if echo "$AUDIT_BODY" | grep -q 'policy.violation'; then
  pass "audit: policy.violation rows recorded"
else
  fail "audit: no policy.violation row"
  echo "$AUDIT_BODY" | head -c 600
fi

echo "=== teardown ==="
cleanup

echo "=== RESULT: $PASS passed, $FAIL failed ==="
[[ "$FAIL" -eq 0 ]]
