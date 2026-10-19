#!/usr/bin/env bash
# filename: tests/live/migration/run.sh
#
# W33-19: boots a hub, bulk-imports 200 generated self-signed certs, then
#   1. scripts/migration-verify.sh against the full manifest must exit 0
#      (100% mapped, 0 unmatched);
#   2. a manifest with one extra random fingerprint must exit 1 (asserted);
#   3. a second bulk-import must add 0 (idempotence).
# Env: KK_MIG_HUB_PORT (default 0 = engine-assigned free port), KK_KEEP.
set -u
set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
WORK="$(mktemp -d /tmp/kk-uat-migration.XXXXXX)"
HUB_DIR="$WORK/hub"
TOKEN=uat-token
N=200

FAILED=0
STEP() { echo; echo "== $* =="; }
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }
DIE()  { echo "FAIL: $*"; exit 1; }

HUB_PID=""
cleanup() {
  [ -n "${KK_KEEP:-}" ] && { echo "KK_KEEP set: leaving $WORK"; return; }
  [ -n "$HUB_PID" ] && kill "$HUB_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

curlj() { curl -sS -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' "$@"; }
jget() { python3 -c 'import json,sys
d=json.load(sys.stdin)
for k in sys.argv[1].split("."):
    d=d.get(k) if isinstance(d,dict) else None
print("" if d is None else d)' "$1" 2>/dev/null; }

free_port() { python3 -c 'import socket
s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
HUB_PORT="${KK_MIG_HUB_PORT:-0}"
[ "$HUB_PORT" = 0 ] && HUB_PORT="$(free_port)"
HUB_BASE="http://127.0.0.1:${HUB_PORT}"

STEP "build + start hub"
mkdir -p "$HUB_DIR/data"
( cd "$REPO_ROOT" && go build -o "$HUB_DIR/kryptkeeper" ./cmd/kryptkeeper ) || DIE "go build failed"
export APP_BOOTSTRAP_TOKEN="$TOKEN" AUTH_MODE=bootstrap APP_CERTIFICATE_PROVIDER=ca \
  APP_DISCOVERY_PROVIDER=db APP_NOTIFICATION_PROVIDER=file KRYPTKEEPER_TLS_DISABLE=true \
  APP_CREDENTIAL_STORE_PASSPHRASE="$(openssl rand -hex 24)" \
  KRYPTKEEPER_KEYSTORE_PASSPHRASE="$(openssl rand -hex 24)" \
  KRYPTKEEPER_DATA_DIR="$HUB_DIR/data" \
  APP_CA_FILE="$HUB_DIR/data/cas.json" APP_TEMPLATE_FILE="$HUB_DIR/data/templates.json" \
  APP_CERTIFICATE_FILE="$HUB_DIR/data/certificates.json" APP_AUDIT_FILE="$HUB_DIR/data/audit.json" \
  APP_CERTS_SUMMARY_FILE="$HUB_DIR/data/certs_summary.json" \
  KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true KRYPTKEEPER_CA_NAME="UAT Root CA" \
  APP_BIND_ADDR=127.0.0.1 PORT="$HUB_PORT"
"$HUB_DIR/kryptkeeper" >"$WORK/hub.log" 2>&1 &
HUB_PID=$!
tries=30
until curl -sS -f -o /dev/null "${HUB_BASE}/api/v1/cas" -H "Authorization: Bearer ${TOKEN}" 2>/dev/null; do
  kill -0 "$HUB_PID" 2>/dev/null || DIE "hub exited during startup, see $WORK/hub.log"
  tries=$((tries - 1)); [ $tries -le 0 ] && DIE "hub never answered /api/v1/cas, see $WORK/hub.log"
  sleep 1
done
PASS "hub answering on $HUB_BASE"

STEP "generate $N self-signed certificates"
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/key.pem" 2>/dev/null || DIE "openssl keygen failed"
: >"$WORK/bundle.pem"; : >"$WORK/manifest.txt"
i=0
while [ $i -lt $N ]; do
  cn="$(printf 'mig-%03d.lab.example' "$i")"
  openssl req -x509 -new -key "$WORK/key.pem" -subj "/CN=${cn}" -days 30 -set_serial "$((1000 + i))" \
    -addext "subjectAltName=DNS:${cn}" -out "$WORK/c.pem" 2>/dev/null || DIE "openssl req failed for $cn"
  cat "$WORK/c.pem" >>"$WORK/bundle.pem"
  openssl x509 -in "$WORK/c.pem" -fingerprint -sha256 -noout | cut -d= -f2 | tr -d ':' | tr 'A-Z' 'a-z' >>"$WORK/manifest.txt"
  i=$((i + 1))
done
[ "$(sort -u "$WORK/manifest.txt" | wc -l | tr -d ' ')" = "$N" ] && PASS "$N distinct fingerprints" || DIE "fingerprints not distinct"

import_bundle() {
  BUNDLE_FILE="$WORK/bundle.pem" python3 -c 'import json,os; print(json.dumps({"format":"pem","bundle":open(os.environ["BUNDLE_FILE"]).read()}))' \
    | curlj -X POST "${HUB_BASE}/api/v1/certificates/bulk-import" --data-binary @-
}

STEP "bulk import"
r1="$(import_bundle)"
[ "$(echo "$r1" | jget data.imported)" = "$N" ] && PASS "imported $N" || FAIL "import want $N: $(echo "$r1" | head -c 300)"

STEP "verify: full manifest must be 100% mapped"
export KK_TOKEN="$TOKEN" KK_HUB_URL="$HUB_BASE"
if "$REPO_ROOT/scripts/migration-verify.sh" --manifest "$WORK/manifest.txt" >"$WORK/v1.out" 2>"$WORK/v1.err"; then
  tail -n1 "$WORK/v1.out" | grep -qx "total=$N mapped=$N unmatched=0 percent=100.0" \
    && PASS "$(tail -n1 "$WORK/v1.out")" || FAIL "unexpected summary: $(tail -n1 "$WORK/v1.out")"
else
  FAIL "migration-verify exited non-zero on the full estate: $(cat "$WORK/v1.err")"
fi

STEP "verify: one unknown fingerprint must fail (expected failure)"
cp "$WORK/manifest.txt" "$WORK/manifest-bad.txt"
openssl rand -hex 32 >>"$WORK/manifest-bad.txt"
"$REPO_ROOT/scripts/migration-verify.sh" --manifest "$WORK/manifest-bad.txt" >"$WORK/v2.out" 2>"$WORK/v2.err"
rc=$?
if [ $rc = 1 ] && tail -n1 "$WORK/v2.out" | grep -q "unmatched=1"; then
  PASS "broken estate rejected with exit 1 ($(tail -n1 "$WORK/v2.out"))"
else
  FAIL "broken estate: want exit 1 and unmatched=1, got exit $rc: $(tail -n1 "$WORK/v2.out")"
fi

STEP "re-import is idempotent"
r2="$(import_bundle)"
[ "$(echo "$r2" | jget data.imported)" = 0 ] && [ "$(echo "$r2" | jget data.skipped_duplicates)" = "$N" ] \
  && PASS "second import added 0 (skipped $N)" || FAIL "second import: $(echo "$r2" | head -c 300)"

echo
[ $FAILED = 0 ] && echo "ALL PASS" || { echo "FAILURES"; exit 1; }
