#!/usr/bin/env bash
# W28-13: prove the scheduled evidence-pack mailer against a REAL SMTP sink.
#
#   1. Mailpit (podman) receives the scheduled SOC 2 evidence pack with the PDF
#      attached (%PDF, > 1000 bytes, compliance-soc2-YYYY-MM-DD.pdf), once.
#   2. With the mailer dead, the scheduler makes exactly 3 send attempts
#      (W28-20), writes an audit row `evidence.delivery_failed`, never marks the
#      schedule sent, and delivers on the next poll once Mailpit is back.
#
# Throwaway fixture values only; nothing real. Ports are distinct from the
# notifications fixture (hub 8101, Mailpit HTTP 8125, SMTP 1125).
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib/podman.sh"
set -u
set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
WORK="$(mktemp -d /tmp/kk-uat-evmail.XXXXXX)"
HUB_DIR=/tmp/kk-uat-evmail-hub
HUB_PORT=8101
HUB_BASE="http://127.0.0.1:${HUB_PORT}"
TOKEN=uat-token
MP_SMTP=1125
MP_HTTP=8125
MP_API="http://127.0.0.1:${MP_HTTP}/api/v1"
MAILPIT_CTR=kk-uat-evmail-mailpit
RECIPIENT="grc@kk-uat.local"
FRAMEWORK=soc2
HUB_LOG="$WORK/hub.log"

FAILED=0
STEP() { echo; echo "== $* =="; }
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }
DIE()  { echo "FAIL: $*"; cleanup; exit 1; }

HUB_PID=""
CLEANED=""
stop_hub() {
  [ -n "$HUB_PID" ] && kill "$HUB_PID" 2>/dev/null || true
  [ -n "$HUB_PID" ] && wait "$HUB_PID" 2>/dev/null || true
  HUB_PID=""
}
# The scheduler lease row is never released on shutdown; clear it so the next
# start's startup scan() runs immediately (same workaround as W19-07).
clear_lease() {
  sqlite3 "$HUB_DIR/data/kryptkeeper.db" "DELETE FROM ha_scheduler_locks WHERE lock_name='evidence-scheduler';" 2>/dev/null || true
}
start_hub() {
  "$HUB_DIR/kryptkeeper" >>"$HUB_LOG" 2>&1 &
  HUB_PID=$!
  local tries=40
  until curl -sS -f -o /dev/null "${HUB_BASE}/api/v1/cas" -H "Authorization: Bearer ${TOKEN}" 2>/dev/null; do
    tries=$((tries - 1)); [ $tries -le 0 ] && DIE "hub never answered /api/v1/cas 200, see $HUB_LOG"
    sleep 1
  done
}
restart_hub() { stop_hub; clear_lease; start_hub; }
cleanup() {
  [ -n "$CLEANED" ] && return
  CLEANED=1
  STEP "cleanup"
  stop_hub
  kk_rm "$MAILPIT_CTR"
  if [ -n "${KK_UAT_KEEP:-}" ]; then
    echo "KK_UAT_KEEP set -- leaving $WORK and $HUB_DIR in place"
  else
    rm -rf "$WORK" "$HUB_DIR"
  fi
}
trap cleanup EXIT

curlj() { curl -sS -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' "$@"; }
jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)" 2>/dev/null; }

wait_for_http() {
  local url=$1 tries=30
  while [ $tries -gt 0 ]; do
    curl -sS -f -o /dev/null "$url" 2>/dev/null && return 0
    sleep 1; tries=$((tries - 1))
  done
  return 1
}
# poll_json URL PYFILTER TRIES: GET until the filter prints something.
poll_json() {
  local url=$1 pyfilter=$2 tries=$3 out
  while [ "$tries" -gt 0 ]; do
    out="$(curl -sS -H "Authorization: Bearer ${TOKEN}" "$url" 2>/dev/null | python3 -c "$pyfilter" 2>/dev/null)"
    [ -n "$out" ] && { echo "$out"; return 0; }
    sleep 1; tries=$((tries - 1))
  done
  return 1
}
mp_count() { curl -sS "${MP_API}/messages" | jget "d['total']"; }
FIND_MSG="
import json,sys
d=json.load(sys.stdin)
for m in d.get('messages', []):
    if m['To'][0]['Address'] == '${RECIPIENT}':
        print(m['ID']); break
"

# ---------------------------------------------------------------------------
STEP "1. start Mailpit"
kk_rm "$MAILPIT_CTR"
podman run -d --name "$MAILPIT_CTR" -p "${MP_SMTP}:1025" -p "${MP_HTTP}:8025" \
  docker.io/axllent/mailpit:latest >/dev/null \
  && PASS "mailpit container up" || DIE "failed to start mailpit (try: podman machine start)"
wait_for_http "${MP_API}/messages" || DIE "mailpit HTTP API never came up"
curl -sS -X DELETE "${MP_API}/messages" >/dev/null
[ "$(mp_count)" = "0" ] && PASS "mailbox empty" || FAIL "mailbox not empty after DELETE"

# ---------------------------------------------------------------------------
STEP "2. build + start hub, seed 5 certificates"
mkdir -p "$HUB_DIR/data"
( cd "$REPO_ROOT" && go build -o "$HUB_DIR/kryptkeeper" ./cmd/kryptkeeper ) \
  && PASS "hub built" || DIE "go build failed"

# KRYPTKEEPER_TLS_DISABLE=true: with APP_CERTIFICATE_PROVIDER=ca the hub would
# otherwise self-issue a TLS listener cert and plain-HTTP curls would fail.
# SMTP_PORT is read directly by NewEvidenceMailerFromEnv (no host-587 workaround).
export APP_BOOTSTRAP_TOKEN="$TOKEN" AUTH_MODE=bootstrap APP_CERTIFICATE_PROVIDER=ca \
  KRYPTKEEPER_TLS_DISABLE=true APP_DISCOVERY_PROVIDER=db \
  APP_CREDENTIAL_STORE_PASSPHRASE='uat-cred-passphrase-32-bytes-long!!' \
  KRYPTKEEPER_KEYSTORE_PASSPHRASE='uat-keystore-passphrase-32-bytes!!' \
  KRYPTKEEPER_DATA_DIR="$HUB_DIR/data" \
  APP_CA_FILE="$HUB_DIR/data/cas.json" \
  APP_TEMPLATE_FILE="$HUB_DIR/data/templates.json" \
  APP_CERTIFICATE_FILE="$HUB_DIR/data/certificates.json" \
  APP_AUDIT_FILE="$HUB_DIR/data/audit.json" \
  APP_CERTS_SUMMARY_FILE="$HUB_DIR/data/certs_summary.json" \
  KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true KRYPTKEEPER_CA_NAME="UAT Root CA" \
  APP_BIND_ADDR=127.0.0.1 PORT="$HUB_PORT" \
  SMTP_HOST=127.0.0.1 SMTP_PORT="$MP_SMTP" SMTP_FROM="evidence@kk-uat.local" \
  EVIDENCE_POLL_HOURS=1 EVIDENCE_RETRY_DELAY_SECONDS=2
start_hub
PASS "hub answering on $HUB_BASE"

BUNDLE=""
for i in 1 2 3 4 5; do
  openssl req -x509 -newkey rsa:2048 -nodes -days 90 -subj "/CN=evmail-${i}.kk-uat.local" \
    -addext "subjectAltName=DNS:evmail-${i}.kk-uat.local" \
    -keyout "$WORK/k${i}.pem" -out "$WORK/c${i}.pem" 2>/dev/null || DIE "openssl failed"
  BUNDLE="${BUNDLE}$(cat "$WORK/c${i}.pem")
"
done
resp="$(python3 -c 'import json,sys; print(json.dumps({"format":"pem","bundle":sys.argv[1]}))' "$BUNDLE" \
  | curlj -X POST "${HUB_BASE}/api/v1/certificates/bulk-import" -d @-)"
imported="$(echo "$resp" | jget "d['data']['imported'] if 'data' in d else d['imported']")"
[ "$imported" = "5" ] && PASS "imported 5 certificates" || DIE "bulk-import did not import 5: $resp"

# ---------------------------------------------------------------------------
STEP "3. create schedule, restart hub so scan() runs at startup"
# "enabled":true is required: POST /reports/evidence/schedules stores a body
# without it as enabled=false, and isDue() never selects a disabled schedule
# (product footgun, reported with W28-13).
SCHED_BODY="{\"enabled\":true,\"framework\":\"${FRAMEWORK}\",\"cadence\":\"weekly\",\"recipients\":[\"${RECIPIENT}\"]}"
resp="$(curlj -w '\n%{http_code}' -X POST "${HUB_BASE}/api/v1/reports/evidence/schedules" -d "$SCHED_BODY")"
code="$(echo "$resp" | tail -1)"; body="$(echo "$resp" | sed '$d')"
SCHED_ID="$(echo "$body" | jget "d['data']['id']")"
{ [ "$code" = "201" ] && [ -n "$SCHED_ID" ]; } && PASS "schedule $SCHED_ID created (201)" || DIE "schedule create failed ($code): $body"
restart_hub
PASS "hub restarted"

# ---------------------------------------------------------------------------
STEP "4. Mailpit receives the pack with the PDF attached"
MSG_ID="$(poll_json "${MP_API}/messages" "$FIND_MSG" 60)"
if [ -z "$MSG_ID" ]; then
  FAIL "no message to ${RECIPIENT} within 60s, see $HUB_LOG"
  tail -20 "$HUB_LOG" | sed 's/^/  hub: /'
else
  PASS "message $MSG_ID delivered to ${RECIPIENT}"
  curl -sS "${MP_API}/message/${MSG_ID}" >"$WORK/msg.json"
  read -r n ctype fname partid < <(python3 -c "
import json
d=json.load(open('$WORK/msg.json'))
a=d.get('Attachments') or []
print(len(a), a[0]['ContentType'] if a else '-', a[0]['FileName'] if a else '-', a[0]['PartID'] if a else '-')")
  [ "$n" = "1" ] && PASS "exactly one attachment" || FAIL "expected 1 attachment, got $n"
  [ "$ctype" = "application/pdf" ] && PASS "attachment is application/pdf" || FAIL "attachment type $ctype"
  echo "$fname" | grep -Eq "^compliance-${FRAMEWORK}-[0-9]{4}-[0-9]{2}-[0-9]{2}\.pdf$" \
    && PASS "filename $fname" || FAIL "filename $fname does not match compliance-${FRAMEWORK}-YYYY-MM-DD.pdf"
  curl -sS "${MP_API}/message/${MSG_ID}/part/${partid}" -o "$WORK/pack.pdf"
  size="$(wc -c <"$WORK/pack.pdf" | tr -d ' ')"
  head -c 4 "$WORK/pack.pdf" | grep -q '^%PDF' && PASS "attachment starts with %PDF" || FAIL "attachment is not a PDF"
  [ "$size" -gt 1000 ] && PASS "pdf is $size bytes (> 1000)" || FAIL "pdf only $size bytes"
  echo "pack: $fname sha256=$(shasum -a 256 "$WORK/pack.pdf" | cut -d' ' -f1) bytes=$size"
  if [ -n "${KK_UAT_PACK_OUT:-}" ]; then cp "$WORK/pack.pdf" "$KK_UAT_PACK_OUT" && echo "pack copied to $KK_UAT_PACK_OUT"; fi
fi

# ---------------------------------------------------------------------------
STEP "5. no duplicate delivery (MarkSent worked)"
sleep 10
[ "$(mp_count)" = "1" ] && PASS "mailbox still holds exactly 1 message" || FAIL "expected 1 message, got $(mp_count)"

# ---------------------------------------------------------------------------
STEP "6. failure path: dead mailer -> 3 attempts -> evidence.delivery_failed"
code="$(curlj -o /dev/null -w '%{http_code}' -X DELETE "${HUB_BASE}/api/v1/reports/evidence/schedules/${SCHED_ID}")"
case "$code" in 200|204) PASS "first schedule deleted ($code)";; *) FAIL "delete schedule returned $code";; esac
resp="$(curlj -X POST "${HUB_BASE}/api/v1/reports/evidence/schedules" -d "$SCHED_BODY")"
SCHED2_ID="$(echo "$resp" | jget "d['data']['id']")"
[ -n "$SCHED2_ID" ] && PASS "second schedule $SCHED2_ID created (due immediately)" || DIE "second schedule create failed: $resp"

podman stop "$MAILPIT_CTR" >/dev/null 2>&1 && PASS "mailpit stopped" || DIE "could not stop mailpit"
LOG_OFFSET="$(wc -l <"$HUB_LOG" | tr -d ' ')"
restart_hub

row="$(poll_json "${HUB_BASE}/api/v1/audit?action=evidence.delivery_failed" "
import json,sys
d=json.load(sys.stdin)
r=d.get('data') or []
if r: print(json.dumps(r[0]))
" 80)"
if [ -n "$row" ]; then
  PASS "audit row evidence.delivery_failed present"
  echo "  row=$row"
  echo "$row" | grep -q "$SCHED2_ID" && PASS "audit row references schedule $SCHED2_ID" || FAIL "audit row does not reference $SCHED2_ID"
  echo "$row" | grep -q '@' && FAIL "audit row leaks an address" || PASS "audit row carries no recipient address"
else
  FAIL "no evidence.delivery_failed audit row within 80s"
fi

# Let any in-flight attempt finish before counting.
sleep 3
attempts="$(tail -n +"$((LOG_OFFSET + 1))" "$HUB_LOG" | grep -c "evidence scheduler: send ${SCHED2_ID} failed")"
[ "$attempts" = "3" ] && PASS "exactly 3 failed attempts logged" || FAIL "expected 3 'evidence scheduler: send ${SCHED2_ID} failed' lines, got $attempts"
tail -n +"$((LOG_OFFSET + 1))" "$HUB_LOG" | grep -q "evidence scheduler: sent " && FAIL "scheduler logged a sent line while mailer was down" || PASS "no 'sent' log while mailer was down"

podman start "$MAILPIT_CTR" >/dev/null 2>&1 && PASS "mailpit restarted" || DIE "could not restart mailpit"
wait_for_http "${MP_API}/messages" || DIE "mailpit HTTP API never came back"
curl -sS -X DELETE "${MP_API}/messages" >/dev/null
restart_hub
MSG2="$(poll_json "${MP_API}/messages" "$FIND_MSG" 60)"
[ -n "$MSG2" ] && PASS "pending schedule delivered after recovery (message $MSG2)" || FAIL "schedule never delivered after mailer recovery (MarkSent called on failure?)"

echo
[ "$FAILED" = "0" ] && echo "ALL STEPS PASSED" || echo "SOME STEPS FAILED"
exit "$FAILED"
