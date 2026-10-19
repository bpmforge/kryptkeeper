#!/usr/bin/env bash
# W23-06: air-gap offline-root quickstart (UC-A02), run against a real hub.
# openssl root (kept in offline/) -> import under dual control -> issuing-CA CSR
# -> offline sign -> complete -> first leaf, timed, with proof the hub never
# held the root key. Writes last-run.json.
#
# Env: HUB_PORT (8097), OPENSSL_BIN (openssl), BUDGET_SECONDS (1800).
set -u -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
HUB_PORT="${HUB_PORT:-8097}"
OPENSSL_BIN="${OPENSSL_BIN:-openssl}"
BUDGET_SECONDS="${BUDGET_SECONDS:-1800}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/kk-offline-root.XXXXXX")"
HUB_BASE="http://127.0.0.1:${HUB_PORT}"
BOOT="uat-token-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
PEPPER="uat-pepper-32-characters-minimum!!"
FAILED=0
HUB_PID=""

STEP() { echo; echo "== $* =="; }
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }
cleanup() {
  [ -n "$HUB_PID" ] && kill "$HUB_PID" 2>/dev/null && wait "$HUB_PID" 2>/dev/null
  rm -rf "$WORK"
}
DIE() { echo "FAIL: $*"; [ -f "$WORK/hub.log" ] && tail -20 "$WORK/hub.log"; cleanup; exit 1; }
trap cleanup EXIT

# kid + secret per human; the hub stores only an HMAC verifier.
mkkey() { # name -> sets <NAME>_TOKEN and appends to KEYS_JSON
  local name="$1" kid="uat${1}" secret verifier
  secret="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  verifier="$(printf '%s' "$secret" | "$OPENSSL_BIN" dgst -sha256 -hmac "$PEPPER" -hex | awk '{print $NF}')"
  KEYS_JSON="${KEYS_JSON:+$KEYS_JSON,}{\"name\":\"$name\",\"kid\":\"$kid\",\"secret_verifier\":\"$verifier\",\"principal_id\":\"$name\",\"role\":\"pki-admin\",\"active\":true}"
  printf -v "$(echo "$name" | tr '[:lower:]' '[:upper:]')_TOKEN" 'kk_%s_%s' "$kid" "$secret"
}
KEYS_JSON=""; mkkey alice; mkkey bob

call() { # token method path [curl args] -> HTTP code; body in $WORK/last.json
  local tok="$1" m="$2" p="$3"; shift 3
  curl -sS -o "$WORK/last.json" -w '%{http_code}' -X "$m" -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' "$HUB_BASE$p" "$@"
}
jget() { python3 -c 'import json,sys
d=json.load(open(sys.argv[2]))
for k in sys.argv[1].split("."):
    d=d[int(k)] if isinstance(d,list) else d[k]
print(d)' "$1" "$WORK/last.json" 2>/dev/null; }
expect() { # label want got
  if [ "$3" = "$2" ]; then PASS "$1 -> $3"; else FAIL "$1 -> $3, want $2: $(head -c 300 "$WORK/last.json")"; fi
}
custody_count() { call "$ALICE_TOKEN" GET /api/v1/reports/key-custody >/dev/null; python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["data"]["keys"] or []))' "$WORK/last.json" 2>/dev/null; }

T0=$(date +%s)
STEP "build and start hub"
mkdir -p "$WORK/hub/data" "$WORK/hub/keys" "$WORK/offline"
(cd "$REPO_ROOT" && go build -o "$WORK/hub/kryptkeeper" ./cmd/kryptkeeper) || DIE "go build"
# A hub boots with no CA only when told which CA is default; the id need not
# exist yet (the offline root is imported after start).
cd "$WORK/hub" && exec env APP_BOOTSTRAP_TOKEN="$BOOT" AUTH_MODE=bootstrap APP_CERTIFICATE_PROVIDER=ca APP_DISCOVERY_PROVIDER=db \
  APP_NOTIFICATION_PROVIDER=file KRYPTKEEPER_TLS_DISABLE=true \
  APP_API_KEY_PEPPER="$PEPPER" APP_API_KEY_AUTH_ENABLED=true APP_API_KEYS_JSON="[$KEYS_JSON]" \
  APP_CREDENTIAL_STORE_PASSPHRASE='uat-cred-passphrase-32-bytes-long!!' \
  KRYPTKEEPER_KEYSTORE_PASSPHRASE='uat-keystore-passphrase-32-bytes!!' \
  APP_TEMPLATE_FILE="$WORK/hub/data/templates.json" KRYPTKEEPER_DATA_DIR="$WORK/hub/data" KRYPTKEEPER_KEYSTORE_DIR="$WORK/hub/keys" \
  KRYPTKEEPER_DEFAULT_CA_ID=offline-root-pending APP_BIND_ADDR=127.0.0.1 PORT="$HUB_PORT" \
  "$WORK/hub/kryptkeeper" >"$WORK/hub.log" 2>&1 &
HUB_PID=$!
up=0
for _ in $(seq 1 60); do
  [ "$(curl -sS -o /dev/null -w '%{http_code}' "$HUB_BASE/readyz" 2>/dev/null)" = 200 ] && { up=1; break; }
  kill -0 "$HUB_PID" 2>/dev/null || DIE "hub exited"
  sleep 1
done
[ "$up" = 1 ] || DIE "hub never ready"
PASS "hub ready on $HUB_BASE (no CA configured, alice+bob provisioned)"

STEP "offline host: generate the root (key never leaves offline/)"
"$OPENSSL_BIN" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 -nodes -days 3650 -subj "/CN=Offline Root" \
  -addext basicConstraints=critical,CA:TRUE,pathlen:1 -addext keyUsage=critical,keyCertSign,cRLSign \
  -keyout "$WORK/offline/root.key" -out "$WORK/offline/root.pem" 2>/dev/null || DIE "openssl root"
PASS "offline root generated"

STEP "custody before any hub key exists (acceptance 2)"
n="$(custody_count)"
[ "$n" = 0 ] && PASS "key-custody lists 0 keys before import" || FAIL "key-custody lists '$n' keys, want 0: $(head -c 300 "$WORK/last.json")"

STEP "import root under dual control"
IMPORT_BODY="$(python3 -c 'import json,sys; print(json.dumps({"name":"Offline Root","type":"root","key_storage_type":"external","certificate_pem":open(sys.argv[1]).read()}))' "$WORK/offline/root.pem")"
expect "alice proposes import" 202 "$(call "$ALICE_TOKEN" POST /api/v1/cas/import -d "$IMPORT_BODY")"
ACTION="$(jget data.action_id)"
[ -n "$ACTION" ] || DIE "no action_id in import response: $(head -c 300 "$WORK/last.json")"
expect "alice self-approve refused" 403 "$(call "$ALICE_TOKEN" POST "/api/v1/pending-actions/$ACTION/approve")"
expect "bootstrap token approve refused" 403 "$(call "$BOOT" POST "/api/v1/pending-actions/$ACTION/approve")"
expect "bob approves" 200 "$(call "$BOB_TOKEN" POST "/api/v1/pending-actions/$ACTION/approve")"
REDEEM="$(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); d["approved_action_id"]=sys.argv[2]; print(json.dumps(d))' "$IMPORT_BODY" "$ACTION")"
expect "alice redeems approved import" 201 "$(call "$ALICE_TOKEN" POST /api/v1/cas/import -d "$REDEEM")"
ROOT_ID="$(jget data.id)"
[ "$(jget data.key_storage_type)" = external ] && PASS "root key_storage_type == external" || FAIL "root key_storage_type: $(jget data.key_storage_type)"
[ -n "$ROOT_ID" ] || DIE "no root id"

STEP "direct issuance from the keyless root is refused"
"$OPENSSL_BIN" ecparam -name prime256v1 -genkey -noout -out "$WORK/leaf.key" 2>/dev/null
"$OPENSSL_BIN" req -new -key "$WORK/leaf.key" -subj "/CN=offline-leaf.example.test" -out "$WORK/leaf.csr" 2>/dev/null
LEAF_CSR_JSON="$(python3 -c 'import json,sys; print(json.dumps(open(sys.argv[1]).read()))' "$WORK/leaf.csr")"
expect "template create" 201 "$(call "$ALICE_TOKEN" POST /api/v1/templates -d '{"name":"offline-leaf","display_name":"Offline leaf","validity_period":"P365D","key_usage":["digitalSignature","keyEncipherment"],"extended_key_usage":["clientAuth"],"allowed_algorithms":["ECDSA","RSA"],"active":true}')"
TPL_ID="$(jget data.id)"
c="$(call "$ALICE_TOKEN" POST /api/v1/certificates -d "{\"ca_id\":\"$ROOT_ID\",\"template_id\":\"$TPL_ID\",\"csr_pem\":$LEAF_CSR_JSON}")"
if [ "$c" = 422 ] && grep -q "no signing key available" "$WORK/last.json"; then PASS "issuance from keyless root -> 422 no signing key available"; else FAIL "issuance from keyless root -> $c: $(head -c 300 "$WORK/last.json")"; fi

STEP "issuing CA CSR"
expect "create intermediate (CSR flow)" 201 "$(call "$ALICE_TOKEN" POST /api/v1/cas -d "{\"name\":\"Offline Issuing\",\"type\":\"intermediate\",\"parent_ca_id\":\"$ROOT_ID\",\"algorithm\":\"ECDSA-P256\",\"subject_cn\":\"Offline Issuing\"}")"
ISS_ID="$(jget data.id)"
[ "$(jget data.status)" = pending_certificate ] && PASS "issuing CA status == pending_certificate" || FAIL "issuing CA status: $(jget data.status)"
jget data.csr_pem > "$WORK/offline/issuing.csr"
grep -q "BEGIN CERTIFICATE REQUEST" "$WORK/offline/issuing.csr" && PASS "CSR received" || DIE "no csr_pem"
n="$(custody_count)"
[ "$n" = 1 ] && PASS "key-custody lists exactly 1 key (the issuing CA's)" || FAIL "key-custody lists '$n' keys, want 1"
if grep -q "$ROOT_ID" "$WORK/last.json"; then FAIL "root CA id appears in key-custody"; else PASS "root CA never appears in key-custody"; fi
if grep -q "$ISS_ID" "$WORK/last.json"; then PASS "the one key belongs to the issuing CA"; else FAIL "issuing CA id not found in key-custody"; fi

STEP "offline sign"
printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' >"$WORK/offline/issuing.ext"
"$OPENSSL_BIN" x509 -req -in "$WORK/offline/issuing.csr" -CA "$WORK/offline/root.pem" -CAkey "$WORK/offline/root.key" \
  -CAcreateserial -days 1825 -sha384 -extfile "$WORK/offline/issuing.ext" -out "$WORK/offline/issuing.pem" 2>/dev/null || DIE "offline sign"
PASS "issuing certificate signed offline"

STEP "complete the issuing CA"
CERT_JSON="$(python3 -c 'import json,sys; print(json.dumps({"certificate_pem":open(sys.argv[1]).read()}))' "$WORK/offline/issuing.pem")"
expect "post signed certificate" 200 "$(call "$ALICE_TOKEN" POST "/api/v1/cas/$ISS_ID/certificate" -d "$CERT_JSON")"
[ "$(jget data.status)" = active ] && PASS "issuing CA status == active" || FAIL "issuing CA status after completion: $(jget data.status)"

STEP "first leaf, verified against the offline root"
expect "issue leaf" 201 "$(call "$ALICE_TOKEN" POST /api/v1/certificates -d "{\"ca_id\":\"$ISS_ID\",\"template_id\":\"$TPL_ID\",\"csr_pem\":$LEAF_CSR_JSON}")"
FP="$(jget data.fingerprint_sha256)"
curl -sS -H "Authorization: Bearer $ALICE_TOKEN" "$HUB_BASE/api/v1/certificates/$FP/download?format=pem" -o "$WORK/leaf.pem"
out="$("$OPENSSL_BIN" verify -CAfile "$WORK/offline/root.pem" -untrusted "$WORK/offline/issuing.pem" "$WORK/leaf.pem" 2>&1)"
if echo "$out" | grep -q ': OK$'; then PASS "openssl verify leaf -> issuing -> offline root: OK"; else FAIL "openssl verify: $out"; fi

STEP "negative extras"
expect "re-post certificate" 409 "$(call "$ALICE_TOKEN" POST "/api/v1/cas/$ISS_ID/certificate" -d "$CERT_JSON")"
c="$(call "$ALICE_TOKEN" DELETE "/api/v1/cas/$ROOT_ID")"
if [ "$c" = 409 ] && grep -qi "child CAs" "$WORK/last.json"; then PASS "delete root with active child -> 409 child CAs"; else FAIL "delete root -> $c: $(head -c 300 "$WORK/last.json")"; fi
n="$(custody_count)"
[ "$n" = 1 ] && PASS "key-custody still lists exactly 1 key after the whole flow" || FAIL "key-custody lists '$n' keys at end, want 1"

T1=$(date +%s); ELAPSED=$((T1 - T0))
STEP "result"
echo "ELAPSED=${ELAPSED}s (budget ${BUDGET_SECONDS}s; machine time only, sneakernet/operator time is extra)"
[ "$ELAPSED" -lt "$BUDGET_SECONDS" ] && PASS "elapsed under budget" || FAIL "elapsed ${ELAPSED}s >= ${BUDGET_SECONDS}s"

MACHINE="$(uname -sm), $(sysctl -n machdep.cpu.brand_string 2>/dev/null || grep -m1 'model name' /proc/cpuinfo | cut -d: -f2), $(( $(sysctl -n hw.memsize 2>/dev/null || echo 0) / 1073741824 )) GiB RAM"
python3 - "$HERE/last-run.json" "$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)" "$("$OPENSSL_BIN" version)" "$ELAPSED" "$BUDGET_SECONDS" "$MACHINE" "$FAILED" <<'PY'
import json,sys,datetime
p,commit,ossl,el,bud,mach,failed=sys.argv[1:8]
json.dump({"date":datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),"commit":commit,"openssl":ossl,
 "elapsed_s":int(el),"budget_s":int(bud),"machine":mach,"ok":failed=="0"},open(p,"w"),indent=2)
open(p,"a").write("\n")
PY
cat "$HERE/last-run.json"
if [ "$FAILED" = 0 ]; then echo "ALL PASS"; else echo "ONE OR MORE STEPS FAILED"; fi
exit "$FAILED"
