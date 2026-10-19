#!/usr/bin/env bash
# W26-24: live UAT of the code-signing lifecycle against a REAL SoftHSM2 token:
# request (hub-generated key in the token) -> second-user approval -> issuance ->
# osslsigncode signature with the HSM-held key verifies; an unapproved request
# yields 0 certificates; the key cannot be exported (CKA_EXTRACTABLE=false); the
# inventory policy-check flags a deliberately non-compliant certificate.
#
# SoftHSM2, pkcs11-tool and osslsigncode are not on most hosts, so by default this
# script builds tests/live/codesign/Dockerfile with podman and re-runs ITSELF
# inside that container (repo mounted read-only at /src). Set KK_CODESIGN_NATIVE=1
# to run directly on a host that has the tools (softhsm2-util, pkcs11-tool,
# osslsigncode, openssl, python3, go with cgo).
#
# Exit codes: 0 all steps passed; 1 a step failed; 77 SKIP (a tool is missing);
# 78 no FAIL but a step is BLOCKED (tooling), which is never reported as a pass.
#
# Env: HUB_PORT (8226)  KEEP_IMAGE=1 (keep the toolbox image)  KK_CODESIGN_NATIVE=1
#      KK_CODESIGN_GOMODCACHE=<dir> (host go mod cache to mount, speeds up the build)
#
# Attestation (FR-P92: a requester CSR needs a YubiKey PIV attestation, and no
# vendor root is shipped yet) is NOT exercised on the success path here: the run
# uses the hub-generated-key path. The attestation success path is PENDING (needs a
# real YubiKey and the Yubico root); only its fail-closed refusal is asserted.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib/podman.sh"
set -u
set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"

# ---------------------------------------------------------------------------
# Host wrapper: run this same script in the toolbox container.
# ---------------------------------------------------------------------------
if [ "${KK_CODESIGN_IN_CONTAINER:-0}" != 1 ] && [ "${KK_CODESIGN_NATIVE:-0}" != 1 ]; then
  command -v podman >/dev/null 2>&1 || { echo "SKIP: podman not installed (or set KK_CODESIGN_NATIVE=1 on a host with softhsm2/osslsigncode)"; exit 77; }
  IMG=localhost/kk-codesign-uat:latest
  CTR="kk-codesign-uat-$$"
  podman build -q -t "$IMG" "$HERE" >/dev/null || { echo "FAIL: podman build of the toolbox image failed"; exit 1; }
  MODARGS=()
  [ -n "${KK_CODESIGN_GOMODCACHE:-}" ] && MODARGS=(-v "$KK_CODESIGN_GOMODCACHE:/root/go/pkg/mod")
  trap 'kk_rm "$CTR"; [ "${KEEP_IMAGE:-0}" = 1 ] || podman rmi -f "$IMG" >/dev/null 2>&1' EXIT
  podman run --rm --name "$CTR" -v "$REPO_ROOT:/src:ro" "${MODARGS[@]}" \
    -e KK_CODESIGN_IN_CONTAINER=1 -e HUB_PORT="${HUB_PORT:-8226}" \
    -e KK_HUB_COMMIT="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null)" \
    "$IMG" bash /src/tests/live/codesign/run.sh
  exit $?
fi

WORK="$(mktemp -d /tmp/kk-uat-codesign.XXXXXX)"
HUB_DIR="$WORK/hub"
HUB_PORT="${HUB_PORT:-8226}"
HUB="http://127.0.0.1:${HUB_PORT}"
BOOT_TOKEN="uat-boot-$(openssl rand -hex 12)"
PEPPER="uat-pepper-32-characters-minimum!!"
TOKEN_LABEL=kk-uat
TOKEN_PIN=1234
TOKEN_SO_PIN=1234
CN="UAT Publisher"

FAILED=0
BLOCKED=0
STEP() { echo; echo "== $* =="; }
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }
BLOCK() { echo "BLOCKED: $*"; BLOCKED=1; }
MEASURE() { echo "MEASURE $*"; }
DIE() { echo "FAIL: $*"; exit 1; }
SKIP() { echo "SKIP: $1 not installed"; exit 77; }
HUB_PID=""
cleanup() {
  STEP "cleanup"
  if [ "$FAILED" != 0 ]; then echo "--- hub.log (last 30) ---"; tail -30 "$WORK/hub.log" 2>/dev/null || true; fi
  [ -n "$HUB_PID" ] && kill "$HUB_PID" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }
# code TOKEN curl-args... -> prints the HTTP status, body to $WORK/last.json
code() { local tok="$1"; shift; curl -sS -o "$WORK/last.json" -w '%{http_code}' -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' "$@"; }
check() { if [ "$2" = "$3" ]; then PASS "$1 -> $3"; else FAIL "$1: want $2, got $3 ($(head -c 240 "$WORK/last.json" 2>/dev/null))"; fi; }
# cert_total <cn>: meta.total of the inventory filtered by common name
cert_total() { code "$T_alice" -G "$HUB/api/v1/certificates" --data-urlencode "q=$1" --data-urlencode "limit=5" >/dev/null; jget 'd["meta"]["total"]' <"$WORK/last.json" 2>/dev/null || echo -1; }
audit_count() { # <action> <outcome|""> -> number of audit rows
  code "$T_alice" -G "$HUB/api/v1/audit" --data-urlencode "action=$1" --data-urlencode "limit=100" >/dev/null
  python3 -c 'import json,sys
d=json.load(sys.stdin); o=sys.argv[1]
print(len([e for e in d["data"] if not o or e["outcome"]==o]))' "$2" <"$WORK/last.json" 2>/dev/null || echo -1
}

# --- identities: alice (requester) and bob (approver), both pki-admin --------
ENTRIES=""
T_alice=""; T_bob=""
mkident() { # name role -> sets T_<name>, appends the JSON entry (secret never printed)
  local name="$1" role="$2" secret verifier
  secret="$(openssl rand -hex 24)"
  verifier="$(printf '%s' "$secret" | openssl dgst -sha256 -hmac "$PEPPER" -hex | awk '{print $NF}')"
  eval "T_$name=kk_uat${name}_${secret}"
  ENTRIES="${ENTRIES:+$ENTRIES,}{\"name\":\"$name\",\"kid\":\"uat$name\",\"secret_verifier\":\"$verifier\",\"principal_id\":\"$name\",\"role\":\"$role\",\"active\":true}"
}

# ---------------------------------------------------------------------------
STEP "0. preflight"
for t in softhsm2-util pkcs11-tool osslsigncode openssl python3 curl go gcc; do
  command -v "$t" >/dev/null 2>&1 || SKIP "$t"
done
[ "$(go env CGO_ENABLED)" = 1 ] || SKIP "cgo (CGO_ENABLED=1)"
PKCS11_LIB="${KRYPTKEEPER_PKCS11_LIB:-$(find /usr/lib /usr/local/lib /opt/homebrew -name libsofthsm2.so 2>/dev/null | head -1)}"
[ -n "$PKCS11_LIB" ] && [ -f "$PKCS11_LIB" ] || SKIP "libsofthsm2.so"
PASS "tools present; SoftHSM2 module $PKCS11_LIB"
MEASURE "date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
MEASURE "hub_commit=${KK_HUB_COMMIT:-$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null)}"
MEASURE "host=$(uname -srm)"
MEASURE "softhsm2=$(softhsm2-util --version 2>&1 | head -1)"
MEASURE "osslsigncode=$(osslsigncode --version 2>&1 | head -1)"
MEASURE "pkcs11_tool=$(pkcs11-tool --version 2>&1 | head -1)"
MEASURE "openssl=$(openssl version)"

# ---------------------------------------------------------------------------
STEP "1. SoftHSM2 token (private SOFTHSM2_CONF) and a hub built -tags pkcs11"
mkdir -p "$WORK/tokens" "$HUB_DIR/data"
export SOFTHSM2_CONF="$WORK/softhsm2.conf"
cat >"$SOFTHSM2_CONF" <<CONF
directories.tokendir = $WORK/tokens
objectstore.backend = file
log.level = INFO
CONF
softhsm2-util --init-token --free --label "$TOKEN_LABEL" --pin "$TOKEN_PIN" --so-pin "$TOKEN_SO_PIN" >"$WORK/init-token.log" 2>&1 \
  && PASS "token '$TOKEN_LABEL' initialised (selected by label, not slot)" || { cat "$WORK/init-token.log"; DIE "softhsm2-util --init-token failed"; }
(cd "$REPO_ROOT" && CGO_ENABLED=1 go build -tags pkcs11 -o "$HUB_DIR/kryptkeeper" ./cmd/kryptkeeper) >"$WORK/build.log" 2>&1 \
  && PASS "hub built with -tags pkcs11" || { tail -20 "$WORK/build.log"; DIE "go build -tags pkcs11 failed"; }
mkident alice pki-admin
mkident bob pki-admin
(
  export APP_BOOTSTRAP_TOKEN="$BOOT_TOKEN" AUTH_MODE=bootstrap APP_CERTIFICATE_PROVIDER=ca \
    APP_DISCOVERY_PROVIDER=db APP_NOTIFICATION_PROVIDER=file KRYPTKEEPER_TLS_DISABLE=true \
    APP_API_KEY_AUTH_ENABLED=true APP_API_KEY_PEPPER="$PEPPER" APP_API_KEYS_JSON="[$ENTRIES]" \
    APP_CREDENTIAL_STORE_PASSPHRASE='uat-cred-passphrase-32-bytes-long!!' \
    KRYPTKEEPER_DB_MODE=sqlite KRYPTKEEPER_DATA_DIR="$HUB_DIR/data" APP_CA_FILE="$HUB_DIR/data/cas.json" \
    APP_TEMPLATE_FILE="$HUB_DIR/data/templates.json" APP_CERTIFICATE_FILE="$HUB_DIR/data/certificates.json" \
    APP_AUDIT_FILE="$HUB_DIR/data/audit.json" APP_CERTS_SUMMARY_FILE="$HUB_DIR/data/certs_summary.json" \
    KRYPTKEEPER_KEY_BACKEND=pkcs11 KRYPTKEEPER_PKCS11_LIB="$PKCS11_LIB" \
    KRYPTKEEPER_PKCS11_TOKEN_LABEL="$TOKEN_LABEL" KRYPTKEEPER_PKCS11_PIN="$TOKEN_PIN" \
    KRYPTKEEPER_CODESIGN_PROTECTED=true \
    KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true KRYPTKEEPER_CA_NAME="UAT Codesign Root CA" \
    APP_BIND_ADDR=127.0.0.1 PORT="$HUB_PORT"
  exec "$HUB_DIR/kryptkeeper"
) >"$WORK/hub.log" 2>&1 &
HUB_PID=$!
for _ in $(seq 1 60); do
  curl -sf "$HUB/healthz" >/dev/null 2>&1 && break
  kill -0 "$HUB_PID" 2>/dev/null || break
  sleep 1
done
curl -sf "$HUB/healthz" >/dev/null 2>&1 && PASS "hub up on $HUB (pkcs11 backend, KRYPTKEEPER_CODESIGN_PROTECTED=true)" || DIE "hub did not come up, see hub.log"
grep -q "key backend: PKCS#11 (HSM)" "$WORK/hub.log" && PASS "hub log confirms the PKCS#11 backend" || FAIL "hub log does not confirm the PKCS#11 backend"
code "$T_alice" "$HUB/api/v1/cas" >/dev/null
CA_ID="$(jget 'd["data"][0]["id"]' <"$WORK/last.json")"
[ -n "$CA_ID" ] && PASS "root CA id=$CA_ID (key in the token)" || DIE "no CA"

# ---------------------------------------------------------------------------
STEP "2. templates (alice): code-signing with require_approval=false, and a serverAuth-only one"
check "create uat-codesign (EKU codeSigning, require_approval=false)" 201 "$(code "$T_alice" -X POST "$HUB/api/v1/templates" \
  -d '{"name":"uat-codesign","display_name":"UAT code signing","extended_key_usage":["codeSigning"],"key_usage":["digitalSignature"],"allowed_algorithms":["ECDSA"],"validity_period":"P90D","require_approval":false,"active":true}')"
TPL_ID="$(jget 'd["data"]["id"]' <"$WORK/last.json" 2>/dev/null)"
[ -n "$TPL_ID" ] || DIE "no template id"
check "create uat-serverauth (no codeSigning)" 201 "$(code "$T_alice" -X POST "$HUB/api/v1/templates" \
  -d '{"name":"uat-serverauth","display_name":"UAT server auth","extended_key_usage":["serverAuth"],"key_usage":["digitalSignature"],"allowed_algorithms":["ECDSA"],"validity_period":"P90D","active":true}')"
SA_TPL="$(jget 'd["data"]["id"]' <"$WORK/last.json" 2>/dev/null)"

# ---------------------------------------------------------------------------
STEP "3. request (alice): 202, no certificate yet"
check "POST /api/v1/codesign/requests" 202 "$(code "$T_alice" -X POST "$HUB/api/v1/codesign/requests" \
  -d "{\"ca_id\":\"$CA_ID\",\"template_id\":\"$TPL_ID\",\"common_name\":\"$CN\",\"algorithm\":\"ECDSA-P256\"}")"
APPROVAL_ID="$(jget 'd["approval_id"]' <"$WORK/last.json" 2>/dev/null)"
KEY_ID="$(jget 'd["key_id"]' <"$WORK/last.json" 2>/dev/null)"
[ -n "$APPROVAL_ID" ] && [ -n "$KEY_ID" ] && PASS "approval_id=$APPROVAL_ID key_id=$KEY_ID" || DIE "202 body lacks approval_id/key_id: $(cat "$WORK/last.json")"
[ "$(cert_total "$CN")" = 0 ] && PASS "inventory holds 0 certificates for CN '$CN' while the request is unapproved" || FAIL "inventory already holds a certificate for '$CN'"

# ---------------------------------------------------------------------------
STEP "4. approval: requester refused, second user approves"
check "alice approves her own request" 403 "$(code "$T_alice" -X POST "$HUB/api/v1/approvals/$APPROVAL_ID/approve")"
[ "$(cert_total "$CN")" = 0 ] && PASS "still 0 certificates after the refused self-approval" || FAIL "a certificate exists after a refused self-approval"
check "bob approves" 201 "$(code "$T_bob" -X POST "$HUB/api/v1/approvals/$APPROVAL_ID/approve")"
LEAF_FP="$(jget 'd["data"]["fingerprint_sha256"]' <"$WORK/last.json" 2>/dev/null)"
[ -n "$LEAF_FP" ] && PASS "certificate issued: $LEAF_FP" || DIE "approval 201 lacks fingerprint_sha256"
[ "$(cert_total "$CN")" = 1 ] && PASS "inventory holds exactly 1 certificate for '$CN' after approval" || FAIL "inventory count for '$CN' is not 1"

# ---------------------------------------------------------------------------
STEP "5. the key lives in the token"
pkcs11-tool --module "$PKCS11_LIB" --token-label "$TOKEN_LABEL" --login --pin "$TOKEN_PIN" --list-objects --type privkey >"$WORK/privkeys.txt" 2>&1
python3 - "$WORK/privkeys.txt" "$KEY_ID" <<'PY' && PASS "pkcs11-tool lists a private key object labelled $KEY_ID" || FAIL "no private key object labelled $KEY_ID in the token"
import sys
blocks = open(sys.argv[1]).read().split("Private Key Object")
sys.exit(0 if any(("label:      " + sys.argv[2]) in b for b in blocks) else 1)
PY

# ---------------------------------------------------------------------------
STEP "6. osslsigncode signs with the HSM-held key and the signature verifies"
curl -sS -H "Authorization: Bearer $T_alice" "$HUB/api/v1/certificates/$LEAF_FP/download?format=pem" -o "$WORK/leaf.pem"
curl -sS -H "Authorization: Bearer $T_alice" "$HUB/api/v1/cas/$CA_ID/chain?format=pem" -o "$WORK/chain.pem"
grep -q "BEGIN CERTIFICATE" "$WORK/leaf.pem" && grep -q "BEGIN CERTIFICATE" "$WORK/chain.pem" && PASS "downloaded the leaf and the CA chain" || DIE "could not download the leaf/chain PEM"
openssl verify -CAfile "$WORK/chain.pem" -purpose any "$WORK/leaf.pem" >"$WORK/leafverify.log" 2>&1 \
  && PASS "leaf verifies against the CA chain (openssl)" || FAIL "leaf does not verify: $(cat "$WORK/leafverify.log")"
# osslsigncode 2.5 (Debian bookworm) cannot sign .ps1 (added in 2.6), so sign a
# tiny Windows PE built with the image's Go toolchain.
mkdir -p "$WORK/pe" && printf 'package main\nfunc main() {}\n' >"$WORK/pe/main.go" \
  && (cd "$WORK/pe" && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 GOFLAGS=-mod=mod go mod init kkuatpe >/dev/null 2>&1; GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o "$WORK/test.exe" .) \
  || FAIL "could not build the test PE"
SIGN_HELP="$(osslsigncode --help 2>&1 || true)"
SIGN_FLAGS=()
# osslsigncode 2.5 + OpenSSL 3 loads the libp11 "pkcs11" engine by name when only
# -pkcs11module is given; passing -pkcs11engine <path> fails ("dynamic_load:init
# failed") on bookworm, so prefer the by-name path when the help lists it.
if echo "$SIGN_HELP" | grep -q -- '-pkcs11module' && [ -n "$(find /usr/lib /usr/local/lib -name pkcs11.so -path '*engines*' 2>/dev/null | head -1)" ]; then
  SIGN_FLAGS=(-pkcs11module "$PKCS11_LIB")
  MEASURE "osslsigncode_path=engine-by-name (pkcs11)"
elif echo "$SIGN_HELP" | grep -q -- '-pkcs11engine'; then
  ENGINE_SO="$(find /usr/lib /usr/local/lib -name pkcs11.so -path '*engines*' 2>/dev/null | head -1)"
  [ -n "$ENGINE_SO" ] && SIGN_FLAGS=(-pkcs11engine "$ENGINE_SO" -pkcs11module "$PKCS11_LIB")
  MEASURE "osslsigncode_path=engine ($ENGINE_SO)"
elif echo "$SIGN_HELP" | grep -q -- '-provider'; then
  PROV_DIR="$(dirname "$(find /usr/lib /usr/local/lib -name pkcs11.so -path '*ossl-modules*' 2>/dev/null | head -1)" 2>/dev/null)"
  SIGN_FLAGS=(-provider pkcs11 -pkcs11module "$PKCS11_LIB")
  [ -n "$PROV_DIR" ] && [ "$PROV_DIR" != . ] && SIGN_FLAGS+=(-providerpath "$PROV_DIR")
  MEASURE "osslsigncode_path=provider (${PROV_DIR:-none})"
fi
SIGNED=0
if [ "${#SIGN_FLAGS[@]}" -eq 0 ]; then
  BLOCK "step 6: neither -pkcs11engine nor a usable -provider pkcs11 path in this osslsigncode / image (tooling)"
else
  if osslsigncode sign "${SIGN_FLAGS[@]}" -certs "$WORK/leaf.pem" -key "pkcs11:token=$TOKEN_LABEL;object=$KEY_ID;type=private" \
       -pass "$TOKEN_PIN" -h sha256 -in "$WORK/test.exe" -out "$WORK/signed.exe" >"$WORK/sign.log" 2>&1 && [ -s "$WORK/signed.exe" ]; then
    PASS "osslsigncode signed test.exe with the key held in SoftHSM2"
    SIGNED=1
  else
    FAIL "osslsigncode sign failed: $(tail -8 "$WORK/sign.log")"
  fi
fi
if [ "$SIGNED" = 1 ]; then
  if osslsigncode verify -in "$WORK/signed.exe" -CAfile "$WORK/chain.pem" >"$WORK/sigverify.log" 2>&1 \
     && grep -qiE 'verification: ok|number of verified signatures: *[1-9]' "$WORK/sigverify.log"; then
    PASS "osslsigncode verify accepts the signature against the hub chain"
    MEASURE "signature_verify=$(grep -iE 'verification|verified' "$WORK/sigverify.log" | tr '\n' ' ')"
  else
    FAIL "osslsigncode verify did not report success: $(tail -8 "$WORK/sigverify.log")"
  fi
fi

# ---------------------------------------------------------------------------
STEP "7. key export fails (CKA_EXTRACTABLE=false)"
python3 - "$WORK/privkeys.txt" "$KEY_ID" <<'PY' && PASS "object $KEY_ID is 'never extractable' in pkcs11-tool's listing" || FAIL "object $KEY_ID is not reported 'never extractable'"
import sys
for b in open(sys.argv[1]).read().split("Private Key Object"):
    if ("label:      " + sys.argv[2]) in b:
        sys.exit(0 if "never extractable" in b else 1)
sys.exit(1)
PY
rm -f "$WORK/out.bin"
if pkcs11-tool --module "$PKCS11_LIB" --token-label "$TOKEN_LABEL" --login --pin "$TOKEN_PIN" --read-object --type privkey --label "$KEY_ID" -o "$WORK/out.bin" >"$WORK/readobj.log" 2>&1 \
   && [ -s "$WORK/out.bin" ]; then
  FAIL "pkcs11-tool read the private key object out of the token ($(wc -c <"$WORK/out.bin") bytes)"
else
  PASS "pkcs11-tool --read-object yields no key bytes ($(tr '\n' ' ' <"$WORK/readobj.log" | head -c 160))"
fi
# Dual control is ON by default: propose, second human approves, proposer redeems.
# The grant gets through the gate so the refusal below is the token's, not the gate's.
EXPORT_BODY='{"passphrase":"uat-export-passphrase"}'
check "alice export is only proposed (dual control)" 202 "$(code "$T_alice" -X POST "$HUB/api/v1/keys/$KEY_ID/export" -d "$EXPORT_BODY")"
EXP="$(jget 'd["data"]["action_id"]' <"$WORK/last.json" 2>/dev/null)"
check "bob approves the export grant" 200 "$(code "$T_bob" -X POST "$HUB/api/v1/pending-actions/$EXP/approve")"
c="$(code "$T_alice" -X POST "$HUB/api/v1/keys/$KEY_ID/export" -d "{\"passphrase\":\"uat-export-passphrase\",\"approved_action_id\":\"$EXP\"}")"
if [ "$c" -ge 400 ] 2>/dev/null && ! grep -q -- '-----BEGIN' "$WORK/last.json"; then
  PASS "approved export of the HSM key refused by the store: HTTP $c, no PEM body"
else
  FAIL "export of the HSM key returned HTTP $c / a PEM body: $(head -c 200 "$WORK/last.json")"
fi

# ---------------------------------------------------------------------------
STEP "8. policy-check flags a non-compliant code-signing certificate; audit rows"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/bad.key" -out "$WORK/bad.pem" -days 30 \
  -subj "/CN=UAT Noncompliant Signer" -addext "extendedKeyUsage=codeSigning" -addext "keyUsage=digitalSignature" >/dev/null 2>&1 \
  || DIE "could not generate the non-compliant certificate"
rm -f "$WORK/bad.key"
BAD_FP="$(openssl x509 -in "$WORK/bad.pem" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f')"
python3 -c "import json,sys; print(json.dumps({'certificate_pem': open(sys.argv[1]).read()}))" "$WORK/bad.pem" >"$WORK/import.json"
check "import the RSA-2048 code-signing certificate" 201 "$(code "$T_alice" -X POST "$HUB/api/v1/certificates/import" --data @"$WORK/import.json")"
check "policy-check (min RSA 3072 bits, max validity 398 days)" 200 "$(code "$T_alice" -X POST "$HUB/api/v1/inventory/code-signing/policy-check" -d '{"min_rsa_key_size_bits":3072,"max_validity_days":398}')"
python3 - "$WORK/last.json" "$BAD_FP" "$LEAF_FP" <<'PY' && PASS "policy-check: violating >= 1, the imported cert is in findings, the HSM cert is compliant" || FAIL "policy-check result does not match: $(head -c 300 "$WORK/last.json")"
import json, sys
d = json.load(open(sys.argv[1]))["data"]
bad, good = sys.argv[2].lower(), sys.argv[3].lower()
fps = [f["fingerprint_sha256"].lower() for f in d["findings"]]
sys.exit(0 if d["violating"] >= 1 and bad in fps and good not in fps and d["evaluated"] >= 2 else 1)
PY
MEASURE "policy_check=$(jget 'dict(evaluated=d["data"]["evaluated"],violating=d["data"]["violating"],compliant=d["data"]["compliant"])' <"$WORK/last.json" 2>/dev/null)"
[ "$(audit_count codesign.policy.check success)" -ge 1 ] && PASS "audit holds codesign.policy.check" || FAIL "audit lacks codesign.policy.check"

check "request against the serverAuth-only template refused" 422 "$(code "$T_alice" -X POST "$HUB/api/v1/codesign/requests" \
  -d "{\"ca_id\":\"$CA_ID\",\"template_id\":\"$SA_TPL\",\"common_name\":\"UAT Not Code Signing\"}")"
[ "$(audit_count codesign.request.deny denied)" -ge 1 ] && PASS "audit holds codesign.request.deny" || FAIL "audit lacks codesign.request.deny"

# FR-P92 fail-closed: a requester CSR (no attestation) for a code-signing template in protected mode.
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/req.key" 2>/dev/null
openssl req -new -key "$WORK/req.key" -subj "/CN=UAT Requester Key" -out "$WORK/req.csr" 2>/dev/null
python3 -c "import json,sys; print(json.dumps({'ca_id':sys.argv[1],'template_id':sys.argv[2],'csr_pem':open(sys.argv[3]).read()}))" "$CA_ID" "$TPL_ID" "$WORK/req.csr" >"$WORK/req.json"
rm -f "$WORK/req.key"
check "requester CSR without attestation refused in protected mode" 422 "$(code "$T_alice" -X POST "$HUB/api/v1/certificates" --data @"$WORK/req.json")"
grep -q "attestation_missing" "$WORK/last.json" && PASS "refusal reason is attestation_missing" || FAIL "refusal lacks attestation_missing: $(head -c 200 "$WORK/last.json")"
[ "$(cert_total "UAT Requester Key")" = 0 ] && PASS "no certificate for the unattested requester CSR" || FAIL "a certificate exists for the unattested requester CSR"
echo "PENDING: attestation success path (YubiKey PIV attestation + Yubico vendor root); needs real hardware, not run"
MEASURE "attestation_path=PENDING"

# ---------------------------------------------------------------------------
STEP "summary"
if [ "$FAILED" -ne 0 ]; then
  echo "ONE OR MORE STEPS FAILED -- see FAIL lines above"; exit 1
elif [ "$BLOCKED" -ne 0 ]; then
  echo "NO FAILURES, BUT A STEP IS BLOCKED (tooling) -- NOT all steps passed"; exit 78
fi
echo "ALL STEPS PASSED (attestation path PENDING)"
exit 0
