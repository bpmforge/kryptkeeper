#!/usr/bin/env bash
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib/podman.sh"
set -uo pipefail

# filename: tests/live/ca-rollover/run.sh
#
# W23-19: live CA rollover. A hub issues through a real ACME client (lego),
# the CA is rolled with ?mode=cross-sign while a renew loop is running, and
# the harness proves: old and new anchors both verify, the client saw 0
# failed renewals across the rollover, and OCSP + CRL verify against the NEW
# key within 60 s. Topology and helper rationale: see tests/live/acme/README.md
# (this script is built on that harness).

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
RUN_DIR="${KK_UAT_RUN_DIR:-$HOME/kk-uat-rollover-run}"   # under $HOME: podman machine on macOS only mounts /Users
NETWORK="kk-uat-rollover"
HUB_NAME="kk-rollover-hub"
HUB_HOST="kk-rollover-hub"
HUB_PORT="8080"
ACME_SERVER="https://$HUB_HOST:$HUB_PORT/acme/directory"
BOOTSTRAP_TOKEN="uat-token"
CA_NAME="UAT Root CA"
LEGO_IMG="docker.io/goacme/lego:latest"

PASS=0
FAIL=0
pass() { echo "PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL+1)); }

curl_hub() {
  podman run --rm --network "$NETWORK" -v "$RUN_DIR/tls-export:/caexport:ro" \
    curlimages/curl:8.10.1 --cacert /caexport/ca.pem "$@"
}

cleanup() {
  # One name per call: podman 4.9 rm -f silently removes nothing when any listed name is already gone.
  kk_rm kk-lego-loop kk-lego kk-lego-post kk-rollover-verify "$HUB_NAME"
  podman network rm "$NETWORK" >/dev/null 2>&1 || true
}

finish() {
  echo "=== teardown ==="
  cleanup
  echo "=== RESULT: $PASS passed, $FAIL failed ==="
  [[ "$FAIL" -eq 0 ]]
  exit $?
}

fp_of() { openssl x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//'; }

echo "=== W23-19 CA rollover: setup ==="
cleanup
trap cleanup EXIT INT TERM
rm -rf "$RUN_DIR"
mkdir -p "$RUN_DIR/bin" "$RUN_DIR/data" "$RUN_DIR/lego" "$RUN_DIR/lego-post" "$RUN_DIR/verify" "$RUN_DIR/tls-export"

echo "--- pre-pulling images ---"
for img in "$LEGO_IMG" curlimages/curl:8.10.1 alpine:3; do
  podman pull -q "$img" >/dev/null 2>&1 || true
done

echo "--- building hub binary (linux/arm64, CGO_ENABLED=0) ---"
if ! (cd "$ROOT_DIR" && GOOS=linux GOARCH="$(kk_goarch)" CGO_ENABLED=0 go build -o "$RUN_DIR/bin/kryptkeeper" ./cmd/kryptkeeper); then
  fail "build hub binary"; trap - EXIT; finish
fi
pass "build hub binary"

podman network create "$NETWORK" >/dev/null
pass "create podman network $NETWORK"

podman run -d --name kk-rollover-verify --network "$NETWORK" -v "$RUN_DIR/verify:/verify" \
  alpine:3 sh -c "apk add --no-cache openssl >/dev/null 2>&1 && sleep 3600" >/dev/null
for _ in $(seq 1 30); do
  podman exec kk-rollover-verify openssl version >/dev/null 2>&1 && break
  sleep 1
done
if podman exec kk-rollover-verify openssl version >/dev/null 2>&1; then
  pass "verify helper ready (openssl on $NETWORK)"
else
  fail "verify helper ready (openssl on $NETWORK)"
fi

echo "NOTE: dual control disabled for this harness (KRYPTKEEPER_KEY_DUAL_CONTROL=false): the 202/approval path is covered by the W23-15 tests and a bash harness has no second human principal"
podman run -d --name "$HUB_NAME" --network "$NETWORK" --hostname "$HUB_HOST" \
  -v "$RUN_DIR/bin/kryptkeeper:/kryptkeeper:ro" \
  -v "$RUN_DIR/data:/data" \
  -v "$RUN_DIR/tls-export:/tls-export" \
  -e APP_BOOTSTRAP_TOKEN="$BOOTSTRAP_TOKEN" -e AUTH_MODE=bootstrap \
  -e APP_CERTIFICATE_PROVIDER=ca -e APP_DISCOVERY_PROVIDER=db -e APP_NOTIFICATION_PROVIDER=file \
  -e KRYPTKEEPER_TLS_SELF_ISSUE=true -e KRYPTKEEPER_TLS_SANS="$HUB_HOST" \
  -e KRYPTKEEPER_TLS_TRUST_EXPORT_DIR=/tls-export \
  -e KRYPTKEEPER_KEY_DUAL_CONTROL=false \
  -e APP_CREDENTIAL_STORE_PASSPHRASE='uat-cred-passphrase-32-bytes-long!!' \
  -e KRYPTKEEPER_KEYSTORE_PASSPHRASE='uat-keystore-passphrase-32-bytes!!' \
  -e KRYPTKEEPER_DATA_DIR=/data \
  -e APP_CA_FILE=/data/cas.json -e APP_TEMPLATE_FILE=/data/templates.json \
  -e APP_CERTIFICATE_FILE=/data/certificates.json -e APP_AUDIT_FILE=/data/audit.json \
  -e APP_CERTS_SUMMARY_FILE=/data/certs_summary.json \
  -e KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true -e KRYPTKEEPER_CA_NAME="$CA_NAME" \
  -e APP_BIND_ADDR="$HUB_HOST" -e PORT="$HUB_PORT" \
  -e KRYPTKEEPER_BASE_URL="https://$HUB_HOST:$HUB_PORT" \
  alpine:3 /kryptkeeper >/dev/null

# Poll, don't sleep: first-boot migrations take well over 3s on a loaded runner
# (the hub logs "starting kryptkeeper" only after they finish).
for _ in $(seq 1 120); do
  podman logs "$HUB_NAME" 2>&1 | grep -q "starting kryptkeeper on $HUB_HOST:$HUB_PORT" && break
  sleep 1
done
if ! podman logs "$HUB_NAME" 2>&1 | grep -q "starting kryptkeeper on $HUB_HOST:$HUB_PORT"; then
  fail "hub startup"; podman logs "$HUB_NAME" 2>&1 | tail -40; trap - EXIT; finish
fi
pass "hub startup"

for _ in $(seq 1 15); do
  [[ -s "$RUN_DIR/tls-export/ca.pem" ]] && break
  sleep 1
done
if [[ -s "$RUN_DIR/tls-export/ca.pem" ]]; then
  pass "hub exported its listener CA to tls-export/ca.pem"
else
  fail "hub exported its listener CA to tls-export/ca.pem"; trap - EXIT; finish
fi

# ---------------------------------------------------------------------------
# 2. resolve the CA and save the pre-rotation anchor
# ---------------------------------------------------------------------------
CA_ID=$(curl_hub -s -H "Authorization: Bearer $BOOTSTRAP_TOKEN" "https://$HUB_HOST:$HUB_PORT/api/v1/cas" | python3 -c "import json,sys; print(json.load(sys.stdin)['data'][0]['id'])" 2>/dev/null || true)
if [[ -n "$CA_ID" ]]; then pass "resolved CA id ($CA_ID)"; else fail "resolved CA id"; trap - EXIT; finish; fi

curl_hub -s -H "Authorization: Bearer $BOOTSTRAP_TOKEN" "https://$HUB_HOST:$HUB_PORT/api/v1/cas/$CA_ID/chain?format=pem" > "$RUN_DIR/verify/ca-old.pem"
if openssl x509 -in "$RUN_DIR/verify/ca-old.pem" -noout -subject >/dev/null 2>&1; then
  pass "saved pre-rotation anchor ca-old.pem"
else
  fail "saved pre-rotation anchor ca-old.pem"; trap - EXIT; finish
fi

# ---------------------------------------------------------------------------
# 3. lego issues a leaf BEFORE rotation
# ---------------------------------------------------------------------------
LEGO_COMMON=(--accept-tos --email uat@example.test --server "$ACME_SERVER" --path /data)
LEGO_ENV=(-e LEGO_CA_CERTIFICATES=/etc/kk-ca/ca.pem -v "$RUN_DIR/tls-export/ca.pem:/etc/kk-ca/ca.pem:ro")

kk_wait_dns "$NETWORK" "$HUB_HOST" || fail "dns: $HUB_HOST did not resolve on $NETWORK (podman DNS blackout after a container removal), so the next step cannot be trusted"
podman run --name kk-lego --network "$NETWORK" --hostname kk-lego \
    -v "$RUN_DIR/lego:/data" "${LEGO_ENV[@]}" "$LEGO_IMG" \
    run "${LEGO_COMMON[@]}" --domains kk-lego --http --http.address :80 \
    > "$RUN_DIR/lego/issue.log" 2>&1
kk_rm kk-lego
if [[ -s "$RUN_DIR/lego/certificates/kk-lego.crt" ]]; then
  cp "$RUN_DIR/lego/certificates/kk-lego.crt" "$RUN_DIR/verify/leaf-pre.pem"
  pass "lego: obtained leaf before rotation"
else
  fail "lego: obtained leaf before rotation"; tail -30 "$RUN_DIR/lego/issue.log"; trap - EXIT; finish
fi
if openssl verify -CAfile "$RUN_DIR/verify/ca-old.pem" "$RUN_DIR/verify/leaf-pre.pem" >/dev/null 2>&1; then
  pass "pre-rotation leaf verifies against old anchor"
else
  fail "pre-rotation leaf verifies against old anchor"
fi

# ---------------------------------------------------------------------------
# 4. background renew loop that overlaps the rollover
# ---------------------------------------------------------------------------
rm -f "$RUN_DIR/lego/fail.log" "$RUN_DIR/lego/iter.log"
kk_wait_dns "$NETWORK" "$HUB_HOST" || fail "dns: $HUB_HOST did not resolve on $NETWORK (podman DNS blackout after a container removal), so the next step cannot be trusted"
podman run -d --name kk-lego-loop --network "$NETWORK" --hostname kk-lego \
    -v "$RUN_DIR/lego:/data" "${LEGO_ENV[@]}" --entrypoint sh "$LEGO_IMG" -c '
for i in $(seq 1 12); do
  if /lego run --accept-tos --email uat@example.test --server '"$ACME_SERVER"' --path /data --domains kk-lego --http --http.address :80 --renew-force --ari-disable --no-random-sleep > /data/loop-$i.log 2>&1; then
    echo "$i $(date +%s) $(sha256sum /data/certificates/kk-lego.crt | cut -d" " -f1)" >> /data/iter.log
  else
    echo "RENEW_FAIL $i $(date +%s)" >> /data/fail.log
  fi
  sleep 5
done' >/dev/null
pass "renew loop container started"
# let at least one in-loop renewal land before the rollover, so the loop is demonstrably live
for _ in $(seq 1 60); do [[ -s "$RUN_DIR/lego/iter.log" ]] && break; sleep 1; done
if [[ -s "$RUN_DIR/lego/iter.log" ]]; then pass "renew loop live before rollover"; else fail "renew loop live before rollover"; fi


# ---------------------------------------------------------------------------
# 5. roll the CA (cross-sign) while the loop keeps renewing
# ---------------------------------------------------------------------------
T0=$(date +%s)
VM_T0=$(podman exec kk-rollover-verify date +%s)   # container-clock twin of T0, to compare with the loop's timestamps
RAW=$(curl_hub -s -w '\n__HTTP__%{http_code}' -X POST -H "Authorization: Bearer $BOOTSTRAP_TOKEN" -H 'Content-Type: application/json' \
  "https://$HUB_HOST:$HUB_PORT/api/v1/cas/$CA_ID/rotate-key?mode=cross-sign" -d '{}' 2>/dev/null || true)
ROLL_CODE="${RAW##*__HTTP__}"
ROLL_JSON="${RAW%$'\n'__HTTP__*}"
if [[ "$ROLL_CODE" == "200" ]]; then pass "rotate-key?mode=cross-sign returned 200"; else fail "rotate-key?mode=cross-sign returned $ROLL_CODE"; echo "$ROLL_JSON" | head -c 400; fi
for f in cross_cert_pem old_cert_pem; do
  out="$RUN_DIR/verify/${f%_cert_pem}.pem"
  echo "$ROLL_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['$f'])" > "$out" 2>/dev/null || true
done
if openssl x509 -in "$RUN_DIR/verify/cross.pem" -noout >/dev/null 2>&1 && openssl x509 -in "$RUN_DIR/verify/old.pem" -noout >/dev/null 2>&1; then
  pass "response carries parseable cross_cert_pem and old_cert_pem"
else
  fail "response carries parseable cross_cert_pem and old_cert_pem"
fi

curl_hub -s -H "Authorization: Bearer $BOOTSTRAP_TOKEN" "https://$HUB_HOST:$HUB_PORT/api/v1/cas/$CA_ID/chain?format=pem" > "$RUN_DIR/verify/ca-new.pem"
OLD_FP=$(fp_of "$RUN_DIR/verify/ca-old.pem"); NEW_FP=$(fp_of "$RUN_DIR/verify/ca-new.pem")
if [[ -n "$NEW_FP" && "$NEW_FP" != "$OLD_FP" ]]; then pass "anchor changed after rollover (old $OLD_FP / new $NEW_FP)"; else fail "anchor changed after rollover"; fi

# ---------------------------------------------------------------------------
# 6. a leaf obtained AFTER the rollover, and the chain checks
# ---------------------------------------------------------------------------
kk_wait_dns "$NETWORK" "$HUB_HOST" || fail "dns: $HUB_HOST did not resolve on $NETWORK (podman DNS blackout after a container removal), so the next step cannot be trusted"
podman run --name kk-lego-post --network "$NETWORK" --hostname kk-lego-post \
    -v "$RUN_DIR/lego-post:/data" "${LEGO_ENV[@]}" "$LEGO_IMG" \
    run "${LEGO_COMMON[@]}" --domains kk-lego-post --http --http.address :80 \
    > "$RUN_DIR/lego-post/issue.log" 2>&1
kk_rm kk-lego-post
if [[ -s "$RUN_DIR/lego-post/certificates/kk-lego-post.crt" ]]; then
  cp "$RUN_DIR/lego-post/certificates/kk-lego-post.crt" "$RUN_DIR/verify/leaf-post.pem"
  pass "lego: obtained leaf after rollover"
else
  fail "lego: obtained leaf after rollover"; tail -30 "$RUN_DIR/lego-post/issue.log"
fi

if openssl verify -CAfile "$RUN_DIR/verify/ca-new.pem" "$RUN_DIR/verify/leaf-post.pem" >/dev/null 2>&1; then
  pass "old+new anchor verify: post-rotation leaf verifies against the NEW anchor"
else
  fail "old+new anchor verify: post-rotation leaf verifies against the NEW anchor"
  openssl verify -CAfile "$RUN_DIR/verify/ca-new.pem" "$RUN_DIR/verify/leaf-post.pem" || true
fi
if openssl verify -CAfile "$RUN_DIR/verify/old.pem" -untrusted "$RUN_DIR/verify/cross.pem" "$RUN_DIR/verify/leaf-post.pem" >/dev/null 2>&1; then
  pass "old+new anchor verify: post-rotation leaf chains to the OLD anchor through the cross-signed bridge"
else
  fail "old+new anchor verify: post-rotation leaf chains to the OLD anchor through the cross-signed bridge"
  openssl verify -CAfile "$RUN_DIR/verify/old.pem" -untrusted "$RUN_DIR/verify/cross.pem" "$RUN_DIR/verify/leaf-post.pem" || true
fi
if openssl verify -CAfile "$RUN_DIR/verify/old.pem" "$RUN_DIR/verify/leaf-pre.pem" >/dev/null 2>&1; then
  pass "pre-rotation leaf still verifies against the old anchor"
else
  fail "pre-rotation leaf still verifies against the old anchor"
fi

# ---------------------------------------------------------------------------
# 8. OCSP and CRL against the NEW key, inside the 60 s window
# ---------------------------------------------------------------------------
ocsp_check() {
  # $1 label, $2 leaf basename in verify/, $3 anchor basename in verify/ (used as -issuer AND -CAfile), $4 wanted status
  local resp
  resp=$(podman exec kk-rollover-verify openssl ocsp -issuer "/verify/$3" -CAfile "/verify/$3" -cert "/verify/$2" \
    -url "https://$HUB_HOST:$HUB_PORT/ocsp" -no_nonce 2>&1) || true
  if echo "$resp" | grep -qi "$4" && echo "$resp" | grep -qi "Response verify OK"; then
    pass "$1: OCSP reports $4 (signature verified)"
  else
    fail "$1: OCSP reports $4 (signature verified)"
    echo "$resp"
  fi
}
ocsp_check "OCSP verified against new key within 60s" leaf-post.pem ca-new.pem good

curl_hub -s "https://$HUB_HOST:$HUB_PORT/crl/$CA_ID.crl" > "$RUN_DIR/verify/post.crl.der"
crl_out=$(openssl crl -inform DER -in "$RUN_DIR/verify/post.crl.der" -CAfile "$RUN_DIR/verify/ca-new.pem" -noout 2>&1 || true)
if echo "$crl_out" | grep -qi "verify OK"; then
  pass "CRL verified against new key within 60s"
else
  fail "CRL verified against new key within 60s"
  echo "$crl_out"
fi
ELAPSED=$(( $(date +%s) - T0 ))
if [[ "$ELAPSED" -le 60 ]]; then pass "OCSP and CRL checks finished ${ELAPSED}s after rollover (<= 60s)"; else fail "OCSP and CRL checks finished ${ELAPSED}s after rollover (> 60s)"; fi

# A relying party that still holds the OLD anchor asks OCSP about a pre-rotation
# leaf: the request names the OLD issuer key hash (W23-16 known limit).
ocsp_check "OCSP for pre-rotation leaf, request naming the OLD issuer key" leaf-pre.pem ca-old.pem good

# ---------------------------------------------------------------------------
# 7. the renew loop must finish with zero failures and have issued after T0
# ---------------------------------------------------------------------------
for _ in $(seq 1 120); do
  [[ "$(podman inspect -f '{{.State.Running}}' kk-lego-loop 2>/dev/null)" == "false" ]] && break
  sleep 2
done
if [[ "$(podman inspect -f '{{.State.Running}}' kk-lego-loop 2>/dev/null)" == "false" ]]; then pass "renew loop finished"; else fail "renew loop finished (timed out)"; fi
FAILS=0; [[ -f "$RUN_DIR/lego/fail.log" ]] && FAILS=$(wc -l < "$RUN_DIR/lego/fail.log" | tr -d ' ')
ITERS=0; [[ -f "$RUN_DIR/lego/iter.log" ]] && ITERS=$(wc -l < "$RUN_DIR/lego/iter.log" | tr -d ' ')
AFTER=$(awk -v t="$VM_T0" '$2 > t' "$RUN_DIR/lego/iter.log" 2>/dev/null | wc -l | tr -d ' ')
echo "renew loop: $ITERS successful renewals, $FAILS failed, $AFTER issued after the rollover started"
if [[ "$FAILS" == "0" && "$ITERS" -ge 1 ]]; then pass "0 failed ACME renewals across rollover"; else fail "0 failed ACME renewals across rollover ($FAILS failed of $((ITERS+FAILS)))"; tail -5 "$RUN_DIR/lego"/loop-*.log 2>/dev/null | tail -30; fi
if [[ "$AFTER" -ge 1 ]]; then pass "renew loop issued $AFTER certificate(s) after the rollover"; else fail "renew loop issued no certificate after the rollover"; fi
if [[ -s "$RUN_DIR/lego/certificates/kk-lego.crt" ]] && openssl verify -CAfile "$RUN_DIR/verify/ca-new.pem" "$RUN_DIR/lego/certificates/kk-lego.crt" >/dev/null 2>&1; then
  pass "the running client's latest certificate chains to the NEW anchor"
else
  fail "the running client's latest certificate chains to the NEW anchor"
fi

echo "--- hub log tail ---"
podman logs "$HUB_NAME" 2>&1 | tail -30

trap - EXIT INT TERM
finish
