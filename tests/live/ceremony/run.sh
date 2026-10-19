#!/usr/bin/env bash
# W23-09 live proof: two-human M-of-N key ceremony and D-122 dual control,
# driven over HTTP against a real hub built from this checkout, backed by a
# throwaway Postgres container.
#
#   A. 2-of-3 ceremony with distinct identities: issuance refused before
#      quorum, allowed after the 2nd approval; bootstrap-token, mcp-agent and
#      repeat approvals refused; an aborted ceremony's CA stays unusable
#   B. dual control on key delete and export: proposer, bootstrap token and
#      mcp-agent cannot approve; a second human can; grants are single-use and
#      bound to the proposing credential
#   C. queue unreachable (Postgres stopped) -> key delete fails closed (503)
#   D. KRYPTKEEPER_KEY_DUAL_CONTROL=false logs the WARNING
#
# Every human comes from APP_API_KEYS_JSON, none is minted with the bootstrap
# token (a bootstrap-minted key resolves to the bootstrap human, RC1-B-01).
# PASS/FAIL per assertion, non-zero exit on any FAIL, writes run-record.txt
# next to this script (no secrets in it), cleans up on exit.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib/podman.sh"
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
WORK="$(mktemp -d /tmp/kkw23cer.XXXXXX)"
RECORD="${RECORD:-$HERE/run-record.txt}"
OPENSSL_BIN="${OPENSSL_BIN:-openssl}"
HUB_PORT="${HUB_PORT:-8239}"
PG_PORT="${PG_PORT:-55439}"
HUB="http://127.0.0.1:$HUB_PORT"
CTR_PG="kkw23cer-pg"
PG_PASS="uat-$(openssl rand -hex 8)"
TOKEN="uat-ceremony-bootstrap-token-$(openssl rand -hex 6)"
PEPPER="uat-pepper-32-characters-minimum!!"
FAILED=0
HUB_PID=""

: >"$RECORD"
say()  { echo "$*" | tee -a "$RECORD"; }
STEP() { say ""; say "=== $* ==="; }
PASS() { say "PASS: $*"; }
FAIL() { say "FAIL: $*"; FAILED=1; }
DIE()  { say "FAIL: $*"; FAILED=1; exit 1; }
stop_hub() { [ -n "$HUB_PID" ] && kill "$HUB_PID" >/dev/null 2>&1 && wait "$HUB_PID" 2>/dev/null; HUB_PID=""; }
cleanup() {
  if [ "$FAILED" = 1 ]; then echo "--- hub log (last 30) ---"; tail -30 "$WORK/hub.log" 2>/dev/null; fi
  stop_hub
  kk_rm "$CTR_PG"
  rm -rf "$WORK"
}
trap cleanup EXIT
jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }
# code TOKEN curl-args... -> prints the HTTP status, body to $WORK/last.json
code() { local tok="$1"; shift; curl -sS -o "$WORK/last.json" -w '%{http_code}' -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' "$@"; }
# check "label" want got
check() { if [ "$2" = "$3" ]; then PASS "$1 -> $3"; else FAIL "$1: want $2, got $3 ($(head -c 200 "$WORK/last.json" 2>/dev/null))"; fi; }
msg() { jget 'd.get("message", d.get("error",""))' <"$WORK/last.json" 2>/dev/null; }

# --- identities (secrets are random per run and never printed) -------------
mkident() { # name role -> sets T_<name>, appends JSON entry
  local name="$1" role="$2" secret verifier
  secret="$(openssl rand -hex 24)"
  verifier="$(printf '%s' "$secret" | openssl dgst -sha256 -hmac "$PEPPER" -hex | awk '{print $NF}')"
  eval "T_$name=kk_uat${name}_${secret}"
  ENTRIES="${ENTRIES:+$ENTRIES,}{\"name\":\"$name\",\"kid\":\"uat$name\",\"secret_verifier\":\"$verifier\",\"principal_id\":\"$name\",\"role\":\"$role\",\"active\":true}"
}
ENTRIES=""
mkident alice pki-admin; mkident bob pki-admin; mkident carol pki-admin; mkident agent mcp-agent
KEYS_JSON="[$ENTRIES]"

say "W23-09 ceremony + dual-control UAT"
say "date:    $(date -u +%Y-%m-%dT%H:%M:%SZ)"
say "commit:  $(git -C "$REPO_ROOT" rev-parse --short HEAD) ($(git -C "$REPO_ROOT" describe --tags --always --dirty 2>/dev/null))"
say "machine: $(uname -srm), $(go version | awk '{print $3}'), podman $(podman --version | awk '{print $NF}')"

STEP "build hub and start Postgres"
(cd "$REPO_ROOT" && CGO_ENABLED=0 go build -o "$WORK/kryptkeeper" ./cmd/kryptkeeper) || DIE "go build failed"
PASS "hub built from this checkout"
kk_rm "$CTR_PG"
podman run -d --name "$CTR_PG" -e POSTGRES_PASSWORD="$PG_PASS" -e POSTGRES_DB=kryptkeeper -e POSTGRES_USER=kryptkeeper \
  -p "127.0.0.1:$PG_PORT:5432" postgres:16-alpine >/dev/null || DIE "could not start postgres container"
pg_wait() { for _ in $(seq 1 60); do podman exec "$CTR_PG" pg_isready -h 127.0.0.1 -U kryptkeeper -d kryptkeeper >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }
pg_wait || DIE "postgres never became ready"
PASS "postgres ready on 127.0.0.1:$PG_PORT"

mkdir -p "$WORK/data"
start_hub() { # extra env assignments as args
  stop_hub
  ( export APP_BOOTSTRAP_TOKEN="$TOKEN" AUTH_MODE=bootstrap APP_CERTIFICATE_PROVIDER=ca \
      APP_API_KEY_AUTH_ENABLED=true APP_API_KEY_PEPPER="$PEPPER" APP_API_KEYS_JSON="$KEYS_JSON" \
      APP_CREDENTIAL_STORE_PASSPHRASE='uat-cred-passphrase-32-bytes-long!!' \
      KRYPTKEEPER_KEYSTORE_PASSPHRASE='uat-keystore-passphrase-32-bytes!!' \
      KRYPTKEEPER_DATA_DIR="$WORK/data" KRYPTKEEPER_KEYSTORE_DIR="$WORK/data/keystore" \
      APP_CA_FILE="$WORK/data/cas.json" APP_TEMPLATE_FILE="$WORK/data/templates.json" \
      APP_CERTIFICATE_FILE="$WORK/data/certificates.json" APP_AUDIT_FILE="$WORK/data/audit.json" \
      APP_CERTS_SUMMARY_FILE="$WORK/data/certs_summary.json" \
      KRYPTKEEPER_DB_MODE=postgres DATABASE_URL="postgres://kryptkeeper:$PG_PASS@127.0.0.1:$PG_PORT/kryptkeeper?sslmode=disable" \
      KRYPTKEEPER_TLS_DISABLE=true APP_BIND_ADDR=127.0.0.1 PORT="$HUB_PORT"
    # The hub refuses to start with no CA at all; the bootstrap root is only the
    # startup default. The ceremony CAs under test are separate, parked roots.
    export KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true KRYPTKEEPER_CA_NAME='UAT Bootstrap Root'
    unset KRYPTKEEPER_KEY_DUAL_CONTROL
    for kv in "$@"; do export "$kv"; done
    exec "$WORK/kryptkeeper" ) >"$WORK/hub.log" 2>&1 &
  HUB_PID=$!
  for _ in $(seq 1 60); do
    curl -sf "$HUB/healthz" >/dev/null 2>&1 && return 0
    kill -0 "$HUB_PID" 2>/dev/null || return 1
    sleep 0.5
  done
  return 1
}
start_hub || DIE "hub did not start"
PASS "hub up with APP_API_KEYS_JSON identities alice, bob, carol (pki-admin) and agent (mcp-agent)"

# --- issuance fixtures ------------------------------------------------------
TPL_ID="$(curl -sS -H "Authorization: Bearer $T_alice" -H 'Content-Type: application/json' -X POST "$HUB/api/v1/templates" \
  -d '{"name":"uat-ceremony","display_name":"UAT ceremony","validity_period":"P30D","key_usage":["digitalSignature"],"extended_key_usage":["serverAuth"],"allowed_algorithms":["ECDSA"],"active":true}' | jget 'd["data"]["id"]')"
[ -n "$TPL_ID" ] || DIE "could not create issuance template"
"$OPENSSL_BIN" ecparam -name prime256v1 -genkey -noout -out "$WORK/leaf.key" 2>/dev/null
"$OPENSSL_BIN" req -new -key "$WORK/leaf.key" -subj "/CN=cer.uat.example" -addext "subjectAltName=DNS:cer.uat.example" -out "$WORK/leaf.csr" 2>/dev/null
issue() { # CA_ID -> http status; leaf JSON in last.json
  python3 -c "import json,sys; json.dump({'ca_id':sys.argv[1],'template_id':sys.argv[2],'csr_pem':open(sys.argv[3]).read()}, open(sys.argv[4],'w'))" \
    "$1" "$TPL_ID" "$WORK/leaf.csr" "$WORK/issue.json"
  code "$T_alice" -X POST "$HUB/api/v1/certificates" --data @"$WORK/issue.json"
}
start_cer() { # name quorum -> status, ceremony JSON in last.json
  code "$T_alice" -X POST "$HUB/api/v1/ceremonies" -d "{\"name\":\"$1\",\"common_name\":\"$1\",\"algorithm\":\"ECDSA-P256\",\"validity_days\":365,\"approvers\":[\"alice\",\"bob\",\"carol\"],\"quorum\":$2}"
}

STEP "A. 2-of-3 ceremony"
check "start ceremony quorum 1 refused" 400 "$(start_cer uat-q1 1)"
check "start ceremony quorum 4 (more than approvers) refused" 400 "$(start_cer uat-q4 4)"
check "start 2-of-3 ceremony (alice)" 201 "$(start_cer uat-root-a 2)"
CER="$(jget 'd["data"]["id"]' <"$WORK/last.json")"; CA_ID="$(jget 'd["data"]["ca_id"]' <"$WORK/last.json")"
[ -n "$CER" ] && [ -n "$CA_ID" ] || DIE "ceremony start returned no ids"
c=$(code "$T_alice" "$HUB/api/v1/cas/$CA_ID"); ST="$(jget 'd["data"]["status"]' <"$WORK/last.json" 2>/dev/null)"
[ "$c" = 200 ] && [ "$ST" = pending_ceremony ] && PASS "CA is parked: status=$ST" || FAIL "CA status $c/$ST"
check "issuance from the parked CA refused" 409 "$(issue "$CA_ID")"
check "bootstrap token approval refused (not an eligible approver)" 400 "$(code "$TOKEN" -X POST "$HUB/api/v1/ceremonies/$CER/approve")"
check "mcp-agent approval refused (not admin role)" 403 "$(code "$T_agent" -X POST "$HUB/api/v1/ceremonies/$CER/approve")"
check "alice approves (1 of 2)" 200 "$(code "$T_alice" -X POST "$HUB/api/v1/ceremonies/$CER/approve")"
check "issuance still refused before quorum" 409 "$(issue "$CA_ID")"
check "alice approving twice refused" 400 "$(code "$T_alice" -X POST "$HUB/api/v1/ceremonies/$CER/approve")"
check "bob approves (2 of 2)" 200 "$(code "$T_bob" -X POST "$HUB/api/v1/ceremonies/$CER/approve")"
CST="$(jget 'd["data"]["status"]' <"$WORK/last.json")"; [ "$CST" = completed ] && PASS "ceremony status=completed" || FAIL "ceremony status=$CST"
check "issuance after the Mth approval" 201 "$(issue "$CA_ID")"
FP="$(jget 'd["data"]["fingerprint_sha256"]' <"$WORK/last.json" 2>/dev/null)"
curl -sS -H "Authorization: Bearer $T_alice" "$HUB/api/v1/certificates/$FP/download?format=pem" -o "$WORK/leaf.pem"
curl -sS -H "Authorization: Bearer $T_alice" "$HUB/api/v1/cas/$CA_ID/chain?format=pem" -o "$WORK/chain.pem"
if "$OPENSSL_BIN" verify -CAfile "$WORK/chain.pem" "$WORK/leaf.pem" >"$WORK/verify.out" 2>&1; then PASS "openssl verify of the leaf against the ceremony CA chain: OK"
else FAIL "openssl verify: $(head -c 200 "$WORK/verify.out")"; fi
check "carol approving a completed ceremony refused" 400 "$(code "$T_carol" -X POST "$HUB/api/v1/ceremonies/$CER/approve")"
check "start second ceremony" 201 "$(start_cer uat-root-b 2)"
CER2="$(jget 'd["data"]["id"]' <"$WORK/last.json")"; CA2="$(jget 'd["data"]["ca_id"]' <"$WORK/last.json")"
check "alice aborts it" 200 "$(code "$T_alice" -X POST "$HUB/api/v1/ceremonies/$CER2/abort")"
AST="$(jget 'd["data"]["status"]' <"$WORK/last.json")"; [ "$AST" = aborted ] && PASS "ceremony status=aborted" || FAIL "status=$AST"
c=$(issue "$CA2"); case "$c" in 4*) PASS "aborted ceremony's CA refuses issuance ($c)" ;; *) FAIL "aborted CA issuance -> $c" ;; esac

STEP "B. dual control on key operations"
check "alice creates key uat-dc-1" 201 "$(code "$T_alice" -X POST "$HUB/api/v1/keys" -d '{"id":"uat-dc-1","algorithm":"ECDSA-P256"}')"
check "alice DELETE uat-dc-1 is only proposed" 202 "$(code "$T_alice" -X DELETE "$HUB/api/v1/keys/uat-dc-1")"
ACT="$(jget 'd["data"]["action_id"]' <"$WORK/last.json")"; [ -n "$ACT" ] || DIE "no action_id"
check "key still readable while the delete is pending" 200 "$(code "$T_alice" "$HUB/api/v1/keys/uat-dc-1")"
check "proposer (alice) cannot approve her own delete" 403 "$(code "$T_alice" -X POST "$HUB/api/v1/pending-actions/$ACT/approve")"
check "bootstrap token cannot approve" 403 "$(code "$TOKEN" -X POST "$HUB/api/v1/pending-actions/$ACT/approve")"
check "mcp-agent cannot approve" 403 "$(code "$T_agent" -X POST "$HUB/api/v1/pending-actions/$ACT/approve")"
check "bob (a different human) approves" 200 "$(code "$T_bob" -X POST "$HUB/api/v1/pending-actions/$ACT/approve")"
check "key is gone after the approval" 404 "$(code "$T_alice" "$HUB/api/v1/keys/uat-dc-1")"

check "alice creates key uat-dc-2" 201 "$(code "$T_alice" -X POST "$HUB/api/v1/keys" -d '{"id":"uat-dc-2","algorithm":"ECDSA-P256"}')"
check "alice export is only proposed" 202 "$(code "$T_alice" -X POST "$HUB/api/v1/keys/uat-dc-2/export" -d '{"passphrase":"uat-export-passphrase"}')"
EXP="$(jget 'd["data"]["action_id"]' <"$WORK/last.json")"
check "bob approves the export grant" 200 "$(code "$T_bob" -X POST "$HUB/api/v1/pending-actions/$EXP/approve")"
check "carol (different human) cannot redeem alice's grant" 403 "$(code "$T_carol" -X POST "$HUB/api/v1/keys/uat-dc-2/export" -d "{\"passphrase\":\"uat-export-passphrase\",\"approved_action_id\":\"$EXP\"}")"
check "alice redeems her approved grant" 200 "$(code "$T_alice" -X POST "$HUB/api/v1/keys/uat-dc-2/export" -d "{\"passphrase\":\"uat-export-passphrase\",\"approved_action_id\":\"$EXP\"}")"
head -c 11 "$WORK/last.json" | grep -q -- '-----BEGIN' && PASS "redeemed export returned an encrypted PEM" || FAIL "export body is not PEM"
check "redeeming the same grant again refused (single use)" 403 "$(code "$T_alice" -X POST "$HUB/api/v1/keys/uat-dc-2/export" -d "{\"passphrase\":\"uat-export-passphrase\",\"approved_action_id\":\"$EXP\"}")"

STEP "C. approval queue unreachable fails closed"
check "alice creates key uat-dc-3" 201 "$(code "$T_alice" -X POST "$HUB/api/v1/keys" -d '{"id":"uat-dc-3","algorithm":"ECDSA-P256"}')"
podman stop "$CTR_PG" >/dev/null 2>&1 && PASS "postgres stopped" || DIE "could not stop postgres"
c=$(code "$T_alice" -m 60 -X DELETE "$HUB/api/v1/keys/uat-dc-3")
check "key DELETE with the queue down" 503 "$c"
podman start "$CTR_PG" >/dev/null 2>&1 && pg_wait && PASS "postgres restarted and healthy" || DIE "postgres did not come back"
sleep 2
c=$(code "$T_alice" "$HUB/api/v1/keys/uat-dc-3")
if [ "$c" != 200 ]; then say "note: hub did not reconnect on its own ($c); restarting it (state lives in postgres)"; start_hub || DIE "hub did not restart"; c=$(code "$T_alice" "$HUB/api/v1/keys/uat-dc-3"); fi
check "key uat-dc-3 still exists (nothing was deleted)" 200 "$c"

STEP "D. opt-out is loud"
start_hub KRYPTKEEPER_KEY_DUAL_CONTROL=false || DIE "hub did not restart with dual control off"
# W30-11 moved the hub to slog: the "WARNING:" text prefix became level=warn.
grep -E '"level":"warn"' "$WORK/hub.log" | grep -q "KRYPTKEEPER_KEY_DUAL_CONTROL=false" && PASS "hub log carries the dual-control WARNING" || FAIL "no WARNING in hub log"

say ""
[ "$FAILED" = 0 ] && say "ALL STEPS PASSED" || say "ONE OR MORE STEPS FAILED"
exit "$FAILED"
