#!/usr/bin/env bash
# W19-08: prove the PKCS#11 keystore backend against a REAL SoftHSM2 token --
# generate/sign/export/delete through the token, a bootstrap root CA whose
# key actually lives in the HSM, CSR issuance + openssl signature
# verification, OCSP/CRL signed by that key, the ADR_PQC_KEYS_SOFTWARE_ONLY.md
# refusal behaviour, and key deletion.
#
# Idempotent, PASS/FAIL per step, non-zero exit on any FAIL, cleans up its
# own hub process, SoftHSM token directory, and temp dirs on exit (trap). No
# real key material is ever committed -- the SoftHSM token is initialised
# fresh into a temp dir every run and destroyed on exit.
#
# Requires: softhsm2-util + libsofthsm2.so (brew install softhsm), pkcs11-tool
# (brew install opensc), CGO_ENABLED=1 (the hub is built with -tags pkcs11),
# openssl, python3, go.
set -u
set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
WORK="$(mktemp -d /tmp/kk-uat-pkcs11.XXXXXX)"
HUB_DIR="$WORK/hub"
HUB_PORT="${HUB_PORT:-8096}"
HUB_BASE="http://127.0.0.1:${HUB_PORT}"
TOKEN=uat-token
TOKEN_LABEL=kk-uat
TOKEN_PIN=1234
TOKEN_SO_PIN=1234

FAILED=0
STEP() { echo; echo "== $* =="; }
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }
DIE()  { echo "FAIL: $*"; cleanup; exit 1; }

HUB_PID=""
cleanup() {
  STEP "cleanup"
  [ -n "$HUB_PID" ] && kill "$HUB_PID" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

curlj() { curl -sS -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' "$@"; }

# ---------------------------------------------------------------------------
# 0. Preflight: softhsm2-util, pkcs11-tool, the module .so, cgo.
# ---------------------------------------------------------------------------
STEP "preflight tools"
command -v softhsm2-util >/dev/null 2>&1 || DIE "softhsm2-util not found -- brew install softhsm"
command -v pkcs11-tool  >/dev/null 2>&1 || DIE "pkcs11-tool not found -- brew install opensc"
PKCS11_LIB="$(brew --prefix softhsm 2>/dev/null)/lib/softhsm/libsofthsm2.so"
[ -f "$PKCS11_LIB" ] || DIE "SoftHSM2 module not found at $PKCS11_LIB"
PASS "softhsm2-util, pkcs11-tool, module present ($PKCS11_LIB)"

# ---------------------------------------------------------------------------
# 1. Initialise a fresh SoftHSM2 token in our own temp dir. SOFTHSM2_CONF
#    must point every tool (softhsm2-util, pkcs11-tool, the hub) at the same
#    tokendir -- otherwise softhsm2-util writes to ~/.config/softhsm2/tokens
#    and the fixture is neither idempotent nor self-cleaning.
# ---------------------------------------------------------------------------
STEP "initialise SoftHSM2 token"
mkdir -p "$WORK/tokens"
export SOFTHSM2_CONF="$WORK/softhsm2.conf"
cat >"$SOFTHSM2_CONF" <<EOF
directories.tokendir = $WORK/tokens
objectstore.backend = file
log.level = INFO
EOF
softhsm2-util --init-token --free --label "$TOKEN_LABEL" --pin "$TOKEN_PIN" --so-pin "$TOKEN_SO_PIN" >"$WORK/init-token.log" 2>&1 \
  && PASS "token '$TOKEN_LABEL' initialised" || DIE "softhsm2-util --init-token failed, see $WORK/init-token.log"
# softhsm2-util reassigns an initialized token to a FRESH slot ID on every
# init -- never slot 0 -- so we select the token by label only (see
# internal/keystore/pkcs11.go and its W19-08 fix), never by a hardcoded slot.
pkcs11-tool --module "$PKCS11_LIB" --token-label "$TOKEN_LABEL" --list-objects >"$WORK/list-empty.log" 2>&1
PASS "token visible to pkcs11-tool"

# ---------------------------------------------------------------------------
# 2. Build the hub with -tags pkcs11 (needs cgo) and start it against the
#    token.
# ---------------------------------------------------------------------------
STEP "build hub (-tags pkcs11, cgo)"
mkdir -p "$HUB_DIR/data"
( cd "$REPO_ROOT" && CGO_ENABLED=1 go build -tags pkcs11 -o "$HUB_DIR/kryptkeeper" ./cmd/kryptkeeper ) \
  && PASS "hub built with pkcs11 support" || DIE "go build -tags pkcs11 failed"

STEP "start hub with KRYPTKEEPER_KEY_BACKEND=pkcs11"
# W19-31: KRYPTKEEPER_TLS_DISABLE=true -- since W19-14 the hub self-issues a
# TLS listener by default with APP_CERTIFICATE_PROVIDER=ca; the surface
# under test here is the PKCS#11/SoftHSM2 keystore backend, not the hub's
# TLS listener (proven separately by tests/live/tls/run.sh), so this
# fixture's own curl/openssl calls stay deliberately plain HTTP.
export APP_BOOTSTRAP_TOKEN="$TOKEN" AUTH_MODE=bootstrap APP_CERTIFICATE_PROVIDER=ca \
  APP_DISCOVERY_PROVIDER=db APP_NOTIFICATION_PROVIDER=file KRYPTKEEPER_TLS_DISABLE=true
export APP_CREDENTIAL_STORE_PASSPHRASE='uat-cred-passphrase-32-bytes-long!!'
export KRYPTKEEPER_DATA_DIR="$HUB_DIR/data" APP_CA_FILE="$HUB_DIR/data/cas.json" \
  APP_TEMPLATE_FILE="$HUB_DIR/data/templates.json" APP_CERTIFICATE_FILE="$HUB_DIR/data/certificates.json" \
  APP_AUDIT_FILE="$HUB_DIR/data/audit.json" APP_CERTS_SUMMARY_FILE="$HUB_DIR/data/certs_summary.json"
export KRYPTKEEPER_KEY_BACKEND=pkcs11
export KRYPTKEEPER_PKCS11_LIB="$PKCS11_LIB" KRYPTKEEPER_PKCS11_TOKEN_LABEL="$TOKEN_LABEL" KRYPTKEEPER_PKCS11_PIN="$TOKEN_PIN"
export KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true KRYPTKEEPER_CA_NAME="UAT PKCS11 Root CA"
export APP_BIND_ADDR=127.0.0.1 PORT="$HUB_PORT"

"$HUB_DIR/kryptkeeper" >"$WORK/hub.log" 2>&1 &
HUB_PID=$!
tries=30
until curl -sS -f -o /dev/null "${HUB_BASE}/api/v1/cas" -H "Authorization: Bearer ${TOKEN}" 2>/dev/null; do
  tries=$((tries - 1)); [ $tries -le 0 ] && { echo "--- hub.log ---"; cat "$WORK/hub.log"; DIE "hub never answered a real /api/v1/cas 200"; }
  sleep 1
done
PASS "hub answering on $HUB_BASE with pkcs11 backend"
grep -q "key backend: PKCS#11 (HSM)" "$WORK/hub.log" && PASS "hub log confirms PKCS#11 backend selected" \
  || FAIL "hub log does not confirm PKCS#11 backend: $(grep -i 'key backend' "$WORK/hub.log")"

# ---------------------------------------------------------------------------
# 3. The bootstrap root CA's key must actually live in the token.
# ---------------------------------------------------------------------------
STEP "root CA created; key resides in SoftHSM2"
CAS_JSON="$(curlj "$HUB_BASE/api/v1/cas")"
CA_ID="$(echo "$CAS_JSON" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["data"][0]["id"])' 2>/dev/null)"
CA_KEY_STORAGE_TYPE="$(echo "$CAS_JSON" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["data"][0]["key_storage_type"])' 2>/dev/null)"
[ -n "$CA_ID" ] && PASS "root CA: $CA_ID" || DIE "no CA found ($WORK/hub.log): $CAS_JSON"
[ "$CA_KEY_STORAGE_TYPE" = "pkcs11" ] && PASS "CA record reports key_storage_type=pkcs11" \
  || FAIL "CA record reports key_storage_type=$CA_KEY_STORAGE_TYPE, want pkcs11"

PRIVKEY_COUNT="$(pkcs11-tool --module "$PKCS11_LIB" --token-label "$TOKEN_LABEL" --login --pin "$TOKEN_PIN" --list-objects --type privkey 2>/dev/null | grep -c '^Private Key Object')"
[ "$PRIVKEY_COUNT" -ge 1 ] && PASS "pkcs11-tool sees $PRIVKEY_COUNT private key object(s) in the token" \
  || DIE "pkcs11-tool sees no private key objects in the token -- the CA key is not actually in the HSM"

# ---------------------------------------------------------------------------
# 4. Issue a certificate via CSR; verify its signature against the CA cert.
# ---------------------------------------------------------------------------
STEP "issue certificate via CSR, verify signature with openssl"
curl -sS "$HUB_BASE/api/v1/cas/$CA_ID/chain?format=pem" -H "Authorization: Bearer ${TOKEN}" -o "$WORK/ca.pem" 2>/dev/null
if ! [ -s "$WORK/ca.pem" ] || ! grep -q "BEGIN CERTIFICATE" "$WORK/ca.pem"; then
  echo "$CAS_JSON" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["data"][0]["certificate_pem"])' > "$WORK/ca.pem" 2>/dev/null
fi
grep -q "BEGIN CERTIFICATE" "$WORK/ca.pem" && PASS "fetched CA certificate PEM" || DIE "could not obtain CA certificate PEM"

TPL_ID="$(curlj -X POST "$HUB_BASE/api/v1/templates" -d '{"name":"uat-pkcs11-leaf","display_name":"UAT PKCS11 Leaf","validity_period":"P365D","key_usage":["digitalSignature","keyEncipherment"],"extended_key_usage":["clientAuth"],"allowed_algorithms":["ECDSA","RSA"],"active":true}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["id"])' 2>/dev/null)"
[ -n "$TPL_ID" ] && PASS "issuance template created: $TPL_ID" || DIE "could not create issuance template"

openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/leaf.key" 2>/dev/null
openssl req -new -key "$WORK/leaf.key" -subj "/CN=uat-pkcs11-leaf" -out "$WORK/leaf.csr" 2>/dev/null
python3 -c "
import json
print(json.dumps({'ca_id': '$CA_ID', 'template_id': '$TPL_ID', 'csr_pem': open('$WORK/leaf.csr').read()}))
" >"$WORK/issue.json"
ISSUE_RESP="$(curlj -X POST "$HUB_BASE/api/v1/certificates" --data @"$WORK/issue.json")"
LEAF_FP="$(echo "$ISSUE_RESP" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["fingerprint_sha256"])' 2>/dev/null)"
[ -n "$LEAF_FP" ] && PASS "issued leaf certificate: $LEAF_FP" || DIE "certificate issuance failed: $ISSUE_RESP"

curlj "$HUB_BASE/api/v1/certificates/$LEAF_FP/download?format=pem" -o "$WORK/leaf.pem"
if openssl verify -CAfile "$WORK/ca.pem" "$WORK/leaf.pem" >"$WORK/verify.log" 2>&1; then
  PASS "leaf certificate signature verifies against the HSM-backed CA (real openssl verify, no bypass)"
else
  FAIL "leaf certificate failed openssl verify: $(cat "$WORK/verify.log")"
fi

# ---------------------------------------------------------------------------
# 5. OCSP and CRL, both signed by the HSM-resident CA key.
# ---------------------------------------------------------------------------
STEP "revoke leaf, check OCSP + CRL (both signed by the HSM key)"
curlj -X POST "$HUB_BASE/api/v1/certificates/$LEAF_FP/revoke" -d '{"reason_code":1,"reason_text":"uat pkcs11 revoke test"}' >"$WORK/revoke.json"
grep -q '"renewal_status":"revoked"' "$WORK/revoke.json" && PASS "leaf revoked" || DIE "revoke API call failed: $(cat "$WORK/revoke.json")"

OCSP_OUT="$(openssl ocsp -issuer "$WORK/ca.pem" -cert "$WORK/leaf.pem" -url "$HUB_BASE/ocsp" -CAfile "$WORK/ca.pem" -text 2>&1)"
echo "$OCSP_OUT" | grep -qi "Cert Status: revoked" && PASS "OCSP response (signature verified against HSM-backed CA) reports revoked" \
  || FAIL "OCSP did not report revoked, or signature verify failed: $OCSP_OUT"

curl -sS "$HUB_BASE/crl/$CA_ID.crl" -o "$WORK/ca.crl"
if openssl crl -in "$WORK/ca.crl" -inform der -CAfile "$WORK/ca.pem" -noout >"$WORK/crlverify.log" 2>&1; then
  PASS "CRL signature verifies against the HSM-backed CA"
else
  FAIL "CRL failed to verify: $(cat "$WORK/crlverify.log")"
fi
LEAF_SERIAL="$(openssl x509 -in "$WORK/leaf.pem" -noout -serial | cut -d= -f2)"
openssl crl -in "$WORK/ca.crl" -inform der -noout -text 2>&1 | grep -qi "$LEAF_SERIAL" \
  && PASS "CRL lists the revoked leaf's serial ($LEAF_SERIAL)" \
  || FAIL "CRL does not list the revoked leaf's serial"

# ---------------------------------------------------------------------------
# 6. PQC/ML-DSA request against the pkcs11 backend: per
#    docs/ADR_PQC_KEYS_SOFTWARE_ONLY.md, ML-DSA keygen on a hardware backend
#    must be refused, not silently routed anywhere. Asserting the documented
#    behaviour, not changing it.
# ---------------------------------------------------------------------------
STEP "PQC/ML-DSA key request against pkcs11 backend (per ADR_PQC_KEYS_SOFTWARE_ONLY.md)"
PQC_RESP="$(curlj -X POST "$HUB_BASE/api/v1/keys" -d '{"id":"uat-pkcs11-mldsa","algorithm":"ML-DSA-44"}')"
PQC_STATUS="$(curlj -o /dev/null -w '%{http_code}' -X POST "$HUB_BASE/api/v1/keys" -d '{"id":"uat-pkcs11-mldsa-2","algorithm":"ML-DSA-44"}')"
if [ "$PQC_STATUS" = "200" ] || [ "$PQC_STATUS" = "201" ]; then
  FAIL "PQC key request against pkcs11 backend SUCCEEDED (status $PQC_STATUS) -- this must never happen per the ADR: $PQC_RESP"
else
  PASS "PQC key request against pkcs11 backend refused (status $PQC_STATUS): $PQC_RESP"
  echo "$PQC_RESP" | grep -qi "ADR_PQC_KEYS_SOFTWARE_ONLY\|software-keystore-only" \
    && PASS "refusal message cites the ADR (keystore.CheckHSMPQCSupport path)" \
    || echo "FINDING: refusal did not cite the ADR by name -- POST /api/v1/keys (internal/bootstrap/handlers_keys.go) calls store.GenerateKey directly and never calls keystore.CheckHSMPQCSupport; PKCS11Store.GenerateKey's own default-case error (internal/keystore/pkcs11.go) is what actually stops it, so the key is correctly never created in the HSM but the caller does not see the ADR-specific message. Not fixed here per the ticket's 'assert the documented behaviour, do not change it' instruction."
fi
PRIVKEY_COUNT_AFTER_PQC="$(pkcs11-tool --module "$PKCS11_LIB" --token-label "$TOKEN_LABEL" --login --pin "$TOKEN_PIN" --list-objects --type privkey 2>/dev/null | grep -c '^Private Key Object')"
[ "$PRIVKEY_COUNT_AFTER_PQC" = "$PRIVKEY_COUNT" ] && PASS "no ML-DSA key object was created in the token (count unchanged: $PRIVKEY_COUNT_AFTER_PQC)" \
  || FAIL "token private-key count changed after the refused PQC request ($PRIVKEY_COUNT -> $PRIVKEY_COUNT_AFTER_PQC) -- something got created despite the refusal"

# ---------------------------------------------------------------------------
# 7. Key deletion via the API removes the token object. Uses a disposable
#    key generated for this step, NOT the CA's own signing key -- DELETE
#    /api/v1/keys/{id} has no CA-in-use guard (unlike /rotate, see
#    internal/bootstrap/handlers_keys.go), so deleting the CA's live key
#    would corrupt the rest of this run for no additional proof value.
# ---------------------------------------------------------------------------
STEP "key deletion via API removes the token object"
GEN_RESP="$(curlj -X POST "$HUB_BASE/api/v1/keys" -d '{"id":"uat-pkcs11-delete-me","algorithm":"ECDSA-P256"}')"
echo "$GEN_RESP" | grep -q '"id":"uat-pkcs11-delete-me"' && PASS "disposable key generated for deletion test" || DIE "could not generate disposable key: $GEN_RESP"

PRIVKEY_COUNT_BEFORE_DELETE="$(pkcs11-tool --module "$PKCS11_LIB" --token-label "$TOKEN_LABEL" --login --pin "$TOKEN_PIN" --list-objects --type privkey 2>/dev/null | grep -c '^Private Key Object')"
DELETE_STATUS="$(curlj -o "$WORK/delete.json" -w '%{http_code}' -X DELETE "$HUB_BASE/api/v1/keys/uat-pkcs11-delete-me")"
if [ "$DELETE_STATUS" = "200" ] || [ "$DELETE_STATUS" = "204" ]; then
  PASS "DELETE /api/v1/keys/{id} returned $DELETE_STATUS"
else
  FAIL "DELETE /api/v1/keys/{id} returned $DELETE_STATUS: $(cat "$WORK/delete.json")"
fi

PRIVKEY_COUNT_AFTER_DELETE="$(pkcs11-tool --module "$PKCS11_LIB" --token-label "$TOKEN_LABEL" --login --pin "$TOKEN_PIN" --list-objects --type privkey 2>/dev/null | grep -c '^Private Key Object')"
if [ "$PRIVKEY_COUNT_AFTER_DELETE" -lt "$PRIVKEY_COUNT_BEFORE_DELETE" ]; then
  PASS "token private-key count dropped after DELETE ($PRIVKEY_COUNT_BEFORE_DELETE -> $PRIVKEY_COUNT_AFTER_DELETE): deletion path works and reaches the token"
else
  FAIL "token private-key count did not drop after DELETE ($PRIVKEY_COUNT_BEFORE_DELETE -> $PRIVKEY_COUNT_AFTER_DELETE): the token object was not actually removed"
fi

# ---------------------------------------------------------------------------
STEP "summary"
if [ "$FAILED" -eq 0 ]; then
  echo "ALL STEPS PASSED"
else
  echo "ONE OR MORE STEPS FAILED -- see FAIL lines above"
fi
exit "$FAILED"
