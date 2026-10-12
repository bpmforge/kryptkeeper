#!/usr/bin/env bash
# W19-07: prove notification and SIEM delivery reach REAL receivers, not
# httptest doubles.
#
#   1. SMTP     -- a real Mailpit container (HTTP API :8025) receives an
#                  email via POST /api/v1/notifications/test-delivery AND via
#                  the product's own daily expiry sweep (real trigger).
#                  KNOWN HUB DEFECT (found live here, filed as W19-18):
#                  cmd/kryptkeeper/main.go's deliveryChannelsFromEnv hardcodes
#                  the SMTP port to 587 and never reads
#                  notifications.smtp_port/username/password, even though
#                  config_store.go has registered all three since W8-13 --
#                  so SMTP_PORT/SMTP_USERNAME/SMTP_PASSWORD are silently
#                  ignored in delivery mode. W19-07's write_scope no longer
#                  covers cmd/kryptkeeper/main.go (docs(board) 6a46886), so
#                  the fix belongs to W19-18, not this ticket -- this fixture
#                  works around it by publishing Mailpit's SMTP listener on
#                  the host's port 587 (what the hub actually dials) as well
#                  as 1025, rather than hiding the defect by "fixing" the
#                  fixture's own SMTP_PORT expectation.
#   2. Webhook  -- a real local HTTP receiver (echo_receiver.py, a separate
#                  process -- not an in-process httptest double) gets the
#                  JSON payload via POST /api/v1/notifications/test-delivery.
#   3. Slack    -- the SAME receiver, on a different path, stands in for a
#                  Slack incoming webhook; asserted Slack-shaped (a "text"
#                  key) since no real Slack workspace is available here.
#   4. SIEM     -- POST /api/v1/integrations/siem/test delivers a JSON event
#                  to the receiver with the expected audit-event fields and
#                  the Splunk-style Authorization header.
#   5. PagerDuty -- W19-27 fixed the defect this section used to describe:
#                  main.go now reads KRYPTKEEPER_PAGERDUTY_EVENTS_URL and
#                  passes it as PagerDutyChannel.Endpoint, so delivery-mode
#                  PagerDuty can be pointed at this fixture's echo receiver
#                  instead of the real Events API. POST
#                  /api/v1/notifications/test-delivery (channel=pagerduty)
#                  delivers an Events API v2 shaped payload (routing_key,
#                  event_action=trigger, payload.summary/severity/source) to
#                  the receiver, proven below same as webhook/slack/SIEM.
#
# Why echo_receiver.py instead of a container image for #2-#4: this fixture
# initially used docker.io/mendhak/http-https-echo, but its Node process
# block-buffers stdout when not attached to a TTY, so `podman logs` lagged
# the real HTTP response by several requests -- caught live: a webhook POST
# that got a 200 immediately had its logged body surface only once later
# slack/siem requests flushed the buffer, reading as "never delivered" when
# it had been. echo_receiver.py fsyncs a JSON line per request, so the poll
# loops below never race a buffer. It is still a real, separate HTTP server
# process the hub actually dials over the network -- not an in-process
# httptest double -- so it satisfies the same "real receiver" bar Mailpit
# does; the UAT plan's ban is on httptest doubles standing in for the
# receiver, not on any receiver that happens to be Go/Python instead of a
# packaged product.
#
# Idempotent, PASS/FAIL per step, non-zero exit on any FAIL, cleans up its
# own container/process/state on exit (trap). No secrets committed: the SIEM
# token and SMTP creds below are throwaway fixture values, never real
# credentials.
set -u
set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
WORK="$(mktemp -d /tmp/kk-uat-notif.XXXXXX)"
HUB_DIR=/tmp/kk-uat-notif-hub
# 8094 collided with a concurrently-running fixture from another session on
# this dev machine during development (a different worktree's k8s UAT hub
# was already bound there) -- 8099 is this fixture's own port.
HUB_PORT=8099
HUB_BASE="http://127.0.0.1:${HUB_PORT}"
TOKEN=uat-token

MAILPIT_SMTP_PORT=1025
# The hub's SMTP port is hardcoded to 587 (W19-18 defect, see header
# comment) -- publish Mailpit there too so this fixture can prove real SMTP
# delivery against the hub AS IT ACTUALLY BEHAVES today, not as it should.
MAILPIT_SMTP_HUB_PORT=587
MAILPIT_HTTP_PORT=8025
ECHO_PORT=9094
MAILPIT_CTR=kk-uat-notif-mailpit
ECHO_LOG="$WORK/echo-requests.jsonl"

SIEM_TOKEN=uat-siem-token-not-a-real-secret

FAILED=0
STEP() { echo; echo "== $* =="; }
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }
DIE()  { echo "FAIL: $*"; cleanup; exit 1; }

HUB_PID=""
ECHO_PID=""
start_hub() {
  "$HUB_DIR/kryptkeeper" >>"$WORK/hub.log" 2>&1 &
  HUB_PID=$!
  local tries=30
  until curl -sS -f -o /dev/null "${HUB_BASE}/api/v1/cas" -H "Authorization: Bearer ${TOKEN}"; do
    tries=$((tries - 1)); [ $tries -le 0 ] && DIE "hub never answered a real /api/v1/cas 200, see $WORK/hub.log"
    sleep 1
  done
}
stop_hub() {
  [ -n "$HUB_PID" ] && kill "$HUB_PID" 2>/dev/null || true
  wait "$HUB_PID" 2>/dev/null || true
  HUB_PID=""
}
cleanup() {
  STEP "cleanup"
  stop_hub
  [ -n "$ECHO_PID" ] && kill "$ECHO_PID" 2>/dev/null || true
  podman rm -f "$MAILPIT_CTR" >/dev/null 2>&1 || true
  if [ -n "${KK_UAT_KEEP:-}" ]; then
    echo "KK_UAT_KEEP set -- leaving $WORK and $HUB_DIR in place"
  else
    rm -rf "$WORK" "$HUB_DIR"
  fi
}
trap cleanup EXIT

curlj() { curl -sS -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' "$@"; }

# ---------------------------------------------------------------------------
# 1. Real receivers: Mailpit (SMTP) and echo_receiver.py (webhook/Slack/SIEM).
# ---------------------------------------------------------------------------
STEP "start Mailpit (real SMTP + HTTP API)"
podman rm -f "$MAILPIT_CTR" >/dev/null 2>&1 || true
podman run -d --name "$MAILPIT_CTR" \
  -p "${MAILPIT_SMTP_PORT}:1025" -p "${MAILPIT_SMTP_HUB_PORT}:1025" -p "${MAILPIT_HTTP_PORT}:8025" \
  docker.io/axllent/mailpit:latest >/dev/null \
  && PASS "mailpit container up (SMTP published on both :${MAILPIT_SMTP_PORT} and :${MAILPIT_SMTP_HUB_PORT} -- see W19-18 note above)" \
  || DIE "failed to start mailpit"

STEP "start echo receiver (webhook / slack-shaped / siem stand-in)"
: >"$ECHO_LOG"
python3 "$HERE/echo_receiver.py" "$ECHO_LOG" "$ECHO_PORT" >"$WORK/echo.log" 2>&1 &
ECHO_PID=$!
PASS "echo receiver started (pid $ECHO_PID, log $ECHO_LOG)"

wait_for_http() {
  local url=$1 tries=30
  while [ $tries -gt 0 ]; do
    curl -sS -f -o /dev/null "$url" 2>/dev/null && return 0
    sleep 1; tries=$((tries - 1))
  done
  return 1
}
wait_for_http "http://127.0.0.1:${MAILPIT_HTTP_PORT}/api/v1/messages" || DIE "mailpit HTTP API never came up"
wait_for_http "http://127.0.0.1:${ECHO_PORT}/health" || DIE "echo receiver never came up, see $WORK/echo.log"
PASS "receivers reachable"

# echo_is_warm: the echo receiver was observed, during this fixture's own
# development, to go through a brief (up to ~20s) window where new
# connections to it stall rather than refuse or accept -- reproduced with a
# bare `curl` from this same shell, unrelated to the hub or to any specific
# channel, so it is receiver/environment warm-up jitter, not a hub defect.
# A single successful *fast* probe (a slow one could just be luck landing
# right at the edge of the stall) is the signal that the window has passed.
wait_echo_warm() {
  local tries=45 t
  while [ $tries -gt 0 ]; do
    t="$(curl -sS -m 2 -o /dev/null -w '%{time_total}' "http://127.0.0.1:${ECHO_PORT}/warmup-probe" -d '{}' 2>/dev/null)"
    if [ -n "$t" ] && python3 -c "import sys; sys.exit(0 if float('$t') < 0.5 else 1)" 2>/dev/null; then
      return 0
    fi
    sleep 1; tries=$((tries - 1))
  done
  return 1
}

# echo_log_has: true if any line logged by echo_receiver.py for `path`
# contains `needle` in its body -- reads the JSONL file directly (fsync'd
# per request), no container-log buffering to race.
echo_log_has() {
  local path=$1 needle=$2
  python3 -c "
import json, sys
path, needle = sys.argv[1], sys.argv[2]
try:
    with open('$ECHO_LOG') as f:
        for line in f:
            rec = json.loads(line)
            if rec['path'] == path and needle in rec['body']:
                sys.exit(0)
except FileNotFoundError:
    pass
sys.exit(1)
" "$path" "$needle"
}
echo_log_record() {
  local path=$1
  python3 -c "
import json, sys
path = sys.argv[1]
try:
    with open('$ECHO_LOG') as f:
        for line in f:
            rec = json.loads(line)
            if rec['path'] == path:
                print(json.dumps(rec))
except FileNotFoundError:
    pass
" "$path"
}

# ---------------------------------------------------------------------------
# 2. Build and run the hub with the real delivery engine wired to the
#    receivers above. APP_NOTIFICATION_PROVIDER=delivery is the switch that
#    turns on internal/notifications/delivery's real SMTP/Slack/webhook
#    channels instead of the file-log stub other fixtures use.
# ---------------------------------------------------------------------------
STEP "build hub"
mkdir -p "$HUB_DIR" "$HUB_DIR/data"
( cd "$REPO_ROOT" && go build -o "$HUB_DIR/kryptkeeper" ./cmd/kryptkeeper ) \
  && PASS "hub built" || DIE "go build failed"

# SMTP_PORT below is set for documentation/parity with env.example, but the
# hub currently IGNORES it (W19-18: deliveryChannelsFromEnv hardcodes 587) --
# that's why Mailpit is published on both MAILPIT_SMTP_PORT and
# MAILPIT_SMTP_HUB_PORT above; the hub actually dials the latter.
# KRYPTKEEPER_TLS_DISABLE=true: W19-14 (landed after this fixture was
# written) made the hub self-issue a TLS listener cert by default whenever
# APP_CERTIFICATE_PROVIDER=ca (set below), which broke every plain
# "http://127.0.0.1:${HUB_PORT}" curl call in this fixture with a TLS
# handshake error -- found live re-running this fixture for W19-27. Every
# assertion here is about notification/SIEM delivery payloads, not the
# listener's transport, so disabling self-issue (rather than rewriting every
# curl call to speak TLS) keeps the fixture testing what it says it tests.
export APP_BOOTSTRAP_TOKEN="$TOKEN" AUTH_MODE=bootstrap APP_CERTIFICATE_PROVIDER=ca \
  KRYPTKEEPER_TLS_DISABLE=true \
  APP_DISCOVERY_PROVIDER=db APP_NOTIFICATION_PROVIDER=delivery \
  APP_CREDENTIAL_STORE_PASSPHRASE='uat-cred-passphrase-32-bytes-long!!' \
  KRYPTKEEPER_KEYSTORE_PASSPHRASE='uat-keystore-passphrase-32-bytes!!' \
  KRYPTKEEPER_DATA_DIR="$HUB_DIR/data" \
  APP_CA_FILE="$HUB_DIR/data/cas.json" \
  APP_TEMPLATE_FILE="$HUB_DIR/data/templates.json" \
  APP_CERTIFICATE_FILE="$HUB_DIR/data/certificates.json" \
  APP_AUDIT_FILE="$HUB_DIR/data/audit.json" \
  APP_CERTS_SUMMARY_FILE="$HUB_DIR/data/certs_summary.json" \
  KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true \
  KRYPTKEEPER_CA_NAME="UAT Root CA" \
  APP_BIND_ADDR=127.0.0.1 PORT="$HUB_PORT" \
  SMTP_HOST=127.0.0.1 SMTP_PORT="$MAILPIT_SMTP_PORT" SMTP_FROM="alerts@kk-uat.local" \
  SLACK_WEBHOOK_URL="http://127.0.0.1:${ECHO_PORT}/slack" \
  WEBHOOK_URL="http://127.0.0.1:${ECHO_PORT}/webhook" \
  SIEM_WEBHOOK_URL="http://127.0.0.1:${ECHO_PORT}/siem" \
  SIEM_WEBHOOK_TOKEN="$SIEM_TOKEN" \
  PAGERDUTY_ROUTING_KEY="uat-pagerduty-routing-key-not-a-real-secret" \
  KRYPTKEEPER_PAGERDUTY_EVENTS_URL="http://127.0.0.1:${ECHO_PORT}/pagerduty" \
  RENEWAL_THRESHOLD_DAYS=5 RENEWAL_POLL_HOURS=1 RENEWAL_ALERT_COOLDOWN_HOURS=1

STEP "start hub"
start_hub
PASS "hub answering on $HUB_BASE"

CA_ID="$(curlj "${HUB_BASE}/api/v1/cas" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["data"][0]["id"])' 2>/dev/null)"
[ -n "$CA_ID" ] && PASS "root CA: $CA_ID" || DIE "no CA found ($HUB_DIR/data/cas.json / hub.log)"

# poll_json: repeatedly GET a URL (mailpit's API, in practice) until a
# python filter script (fed the JSON on stdin) prints something truthy on
# stdout, or the tries run out.
poll_json() {
  local url=$1 pyfilter=$2 tries=$3 out
  while [ "$tries" -gt 0 ]; do
    out="$(curl -sS "$url" 2>/dev/null | python3 -c "$pyfilter" 2>/dev/null)"
    [ -n "$out" ] && { echo "$out"; return 0; }
    sleep 1; tries=$((tries - 1))
  done
  return 1
}

# poll_echo: repeatedly check echo_log_has until it's true or tries run out.
poll_echo() {
  local path=$1 needle=$2 tries=$3
  while [ "$tries" -gt 0 ]; do
    echo_log_has "$path" "$needle" && return 0
    sleep 1; tries=$((tries - 1))
  done
  return 1
}

# ---------------------------------------------------------------------------
# 3. Channel 1 -- SMTP via the documented test-send endpoint
#    (POST /api/v1/notifications/test-delivery), the product's own manual
#    "send me a test notification" trigger.
# ---------------------------------------------------------------------------
STEP "[smtp] POST /api/v1/notifications/test-delivery (channel=email)"
SMTP_TARGET="uat-test-delivery@kk-uat.local"
SMTP_MARKER="uat-marker-$(date +%s)-smtp-test-delivery"
resp="$(curlj -X POST "${HUB_BASE}/api/v1/notifications/test-delivery" -d "$(python3 -c "import json; print(json.dumps({'channel':'email','target':'$SMTP_TARGET','message':'$SMTP_MARKER'}))")")"
echo "  resp=$resp"
status="$(echo "$resp" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["delivery"]["status"])' 2>/dev/null)"
[ "$status" = "queued" ] && PASS "test-delivery accepted (status=queued)" || FAIL "test-delivery not accepted: $resp"

STEP "[smtp] Mailpit receives the email"
found="$(poll_json "http://127.0.0.1:${MAILPIT_HTTP_PORT}/api/v1/messages" "
import json,sys
d=json.load(sys.stdin)
for m in d.get('messages', []):
    if m['To'][0]['Address'] == '$SMTP_TARGET':
        print(m['ID'])
        break
" 20)"
if [ -n "$found" ]; then
  body="$(curl -sS "http://127.0.0.1:${MAILPIT_HTTP_PORT}/api/v1/message/${found}")"
  if echo "$body" | python3 -c "import json,sys; d=json.load(sys.stdin); sys.exit(0 if '$SMTP_MARKER' in d.get('Text','') else 1)"; then
    PASS "[smtp] Mailpit message $found To=$SMTP_TARGET contains marker"
  else
    FAIL "[smtp] Mailpit message $found found but body missing marker"
  fi
else
  FAIL "[smtp] no message to $SMTP_TARGET appeared in Mailpit within 20s"
fi

# ---------------------------------------------------------------------------
# 4. Channel 2 -- generic webhook via test-delivery.
# ---------------------------------------------------------------------------
STEP "[webhook] wait for echo receiver to be warm (see wait_echo_warm above)"
wait_echo_warm && echo "  echo receiver responding fast" || echo "  echo receiver never stabilized in 45s -- proceeding anyway"

STEP "[webhook] POST /api/v1/notifications/test-delivery (channel=webhook)"
WEBHOOK_MARKER="uat-marker-$(date +%s)-webhook-test-delivery"
resp="$(curlj -X POST "${HUB_BASE}/api/v1/notifications/test-delivery" -d "$(python3 -c "import json; print(json.dumps({'channel':'webhook','target':'unused','message':'$WEBHOOK_MARKER'}))")")"
echo "  resp=$resp"

STEP "[webhook] echo receiver records the delivered JSON payload"
# The worker retries up to 3x with 5s/10s backoff (delivery.go's
# NewWorker(channels, maxRetries, 5*time.Second) via
# notification_delivery_provider.go), so a transient first-attempt failure
# can legitimately take ~15s to resolve -- give this margin.
if poll_echo "/webhook" "$WEBHOOK_MARKER" 30; then
  PASS "[webhook] echo receiver recorded a request containing the marker"
else
  FAIL "[webhook] marker never appeared at the echo receiver (see $ECHO_LOG)"
fi

# ---------------------------------------------------------------------------
# 5. Channel 3 -- Slack-shaped payload via test-delivery. No real Slack
#    workspace is available; this proves the hub POSTs a Slack-incoming-
#    webhook-shaped body ({"text": ...}) to the configured URL, which is all
#    a Slack webhook receiver actually looks at.
# ---------------------------------------------------------------------------
STEP "[slack] POST /api/v1/notifications/test-delivery (channel=slack)"
SLACK_MARKER="uat-marker-$(date +%s)-slack-test-delivery"
resp="$(curlj -X POST "${HUB_BASE}/api/v1/notifications/test-delivery" -d "$(python3 -c "import json; print(json.dumps({'channel':'slack','target':'unused','message':'$SLACK_MARKER'}))")")"
echo "  resp=$resp"

STEP "[slack] echo receiver records a Slack-shaped payload ({\"text\": ...})"
if poll_echo "/slack" "$SLACK_MARKER" 30; then
  record="$(echo_log_record "/slack" | tail -1)"
  echo "  record=$record"
  if echo "$record" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); j=json.loads(d['body']); sys.exit(0 if 'text' in j else 1)"; then
    PASS "[slack] echo receiver recorded a Slack-shaped ({\"text\":...}) payload with the marker -- NOTE: a real Slack workspace was NOT available; this proves the outbound shape only"
  else
    FAIL "[slack] marker arrived but the payload has no top-level 'text' key -- not Slack-shaped"
  fi
else
  FAIL "[slack] marker never appeared at the echo receiver (see $ECHO_LOG)"
fi

# ---------------------------------------------------------------------------
# 6. SIEM -- POST /api/v1/integrations/siem/test.
# ---------------------------------------------------------------------------
STEP "[siem] POST /api/v1/integrations/siem/test"
resp="$(curlj -X POST "${HUB_BASE}/api/v1/integrations/siem/test")"
echo "  resp=$resp"
webhook_ok="$(echo "$resp" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["webhook_ok"])' 2>/dev/null)"
[ "$webhook_ok" = "True" ] && PASS "[siem] router reports webhook_ok=true" || FAIL "[siem] router did not report success: $resp"

STEP "[siem] echo receiver recorded a well-formed JSON event with the audit fields + Splunk auth header"
if poll_echo "/siem" "siem.test" 30; then
  record="$(echo_log_record "/siem" | tail -1)"
  echo "  record=$record"
  ok="$(echo "$record" | python3 -c "
import json, sys
rec = json.loads(sys.stdin.read())
body = json.loads(rec['body'])
auth = rec['headers'].get('authorization', '')
checks = [
    body.get('event_type') == 'siem.test',
    body.get('resource_type') == 'integration',
    body.get('resource_id') == 'siem',
    auth == 'Splunk uat-siem-token-not-a-real-secret',
]
print('OK' if all(checks) else 'MISSING:' + repr(list(zip(['event_type','resource_type','resource_id','auth'], checks))))
")"
  if [ "$ok" = "OK" ]; then
    PASS "[siem] event_type/resource_type/resource_id + Splunk Authorization header all present"
  else
    FAIL "[siem] siem.test event arrived but one or more expected fields/headers were missing: $ok"
  fi
else
  FAIL "[siem] no siem.test event ever appeared at the echo receiver"
fi

# ---------------------------------------------------------------------------
# 6b. PagerDuty -- W19-27: KRYPTKEEPER_PAGERDUTY_EVENTS_URL (set above) points
#     delivery-mode PagerDuty at the echo receiver instead of the real
#     Events API, proving the Events API v2 payload shape reaches a real
#     receiver over the network.
# ---------------------------------------------------------------------------
STEP "[pagerduty] POST /api/v1/notifications/test-delivery (channel=pagerduty)"
PD_MARKER="uat-marker-$(date +%s)-pagerduty-test-delivery"
resp="$(curlj -X POST "${HUB_BASE}/api/v1/notifications/test-delivery" -d "$(python3 -c "import json; print(json.dumps({'channel':'pagerduty','target':'unused','message':'$PD_MARKER'}))")")"
echo "  resp=$resp"

STEP "[pagerduty] echo receiver records an Events API v2 shaped payload"
if poll_echo "/pagerduty" "$PD_MARKER" 30; then
  record="$(echo_log_record "/pagerduty" | tail -1)"
  echo "  record=$record"
  ok="$(echo "$record" | python3 -c "
import json, sys
rec = json.loads(sys.stdin.read())
body = json.loads(rec['body'])
payload = body.get('payload', {})
checks = [
    body.get('routing_key') == 'uat-pagerduty-routing-key-not-a-real-secret',
    body.get('event_action') == 'trigger',
    '$PD_MARKER' in payload.get('summary', ''),
    payload.get('source') == 'kryptkeeper',
    'severity' in payload,
]
print('OK' if all(checks) else 'MISSING:' + repr(list(zip(['routing_key','event_action','summary','source','severity'], checks))))
")"
  if [ "$ok" = "OK" ]; then
    PASS "[pagerduty] routing_key/event_action/payload.summary/source/severity all present"
  else
    FAIL "[pagerduty] event arrived but one or more expected fields were wrong: $ok"
  fi
else
  FAIL "[pagerduty] marker never appeared at the echo receiver (see $ECHO_LOG)"
fi

# ---------------------------------------------------------------------------
# 7. The REAL product trigger, not just the manual test-send endpoint: issue
#    a near-expiry certificate with an owner email, then restart the hub so
#    RenewalScheduler.Start()'s immediate on-startup scan (runScan) finds it
#    and calls notifProvider.TestDelivery through the exact same delivery
#    engine -- proving the daily expiry sweep a pilot partner actually
#    depends on reaches a real inbox, not just the manual test button.
#    (RENEWAL_POLL_HOURS floors at whole hours, so a restart -- which reruns
#    the immediate startup scan -- is how this fixture forces a tick inside
#    a UAT run rather than waiting an hour.)
# ---------------------------------------------------------------------------
STEP "[sweep] create short-validity template"
TEMPLATE_RESP="$(curlj -X POST "${HUB_BASE}/api/v1/templates" -d '{
  "name": "uat-notif-shortlived",
  "display_name": "UAT short-lived cert (expiry sweep)",
  "allowed_algorithms": ["ECDSA"],
  "key_usage": ["digitalSignature", "keyEncipherment"],
  "extended_key_usage": ["serverAuth"],
  "validity_period": "48h",
  "active": true
}')"
TEMPLATE_ID="$(echo "$TEMPLATE_RESP" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["id"])' 2>/dev/null)"
[ -n "$TEMPLATE_ID" ] && PASS "template: $TEMPLATE_ID" || FAIL "template create failed: $TEMPLATE_RESP"

SWEEP_OWNER="uat-sweep-owner@kk-uat.local"
FP=""
if [ -n "$TEMPLATE_ID" ]; then
  STEP "[sweep] issue a certificate expiring in 48h (inside the 5-day RENEWAL_THRESHOLD_DAYS)"
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$WORK/sweep.key" -out "$WORK/sweep.csr" \
    -subj "/CN=kk-uat-sweep.local" -addext "subjectAltName=DNS:kk-uat-sweep.local" >/dev/null 2>&1
  csr_json="$(python3 -c "import json; print(json.dumps(open('$WORK/sweep.csr').read()))")"
  issue_resp="$(curlj -X POST "${HUB_BASE}/api/v1/certificates" -d "{\"ca_id\":\"${CA_ID}\",\"template_id\":\"${TEMPLATE_ID}\",\"csr_pem\":${csr_json}}")"
  FP="$(echo "$issue_resp" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["fingerprint_sha256"])' 2>/dev/null)"
  [ -n "$FP" ] && PASS "[sweep] issued: $FP (validity 48h)" || FAIL "[sweep] issue failed: $issue_resp"
fi

if [ -n "$FP" ]; then
  STEP "[sweep] set ownership so the scheduler has somewhere to notify"
  own_resp="$(curlj -X PATCH "${HUB_BASE}/api/v1/certificates/${FP}/ownership" -d "$(python3 -c "import json; print(json.dumps({'owner_email':'$SWEEP_OWNER'}))")")"
  echo "  resp=$own_resp"
  echo "$own_resp" | python3 -c 'import json,sys; json.load(sys.stdin)["data"]' >/dev/null 2>&1 \
    && PASS "[sweep] ownership set: $SWEEP_OWNER" || FAIL "[sweep] ownership update failed: $own_resp"

  STEP "[sweep] restart hub to force the scheduler's immediate startup scan"
  stop_hub
  # ha_coordinator.go's HA lock (ha_scheduler_locks) is unconditionally on
  # for every replica sharing this data dir's sqlite DB, with NO release-on-
  # shutdown path by design (comment: "no heartbeat channel, unlock RPC ...
  # needed for failover" -- leases only lapse on their own TTL). This
  # fixture's own first hub instance already took a 2*RENEWAL_POLL_HOURS = 2h
  # lease for "renewal-scheduler" the moment it started (with a replica ID
  # that dies with it and never renews) -- killing that process does NOT
  # release the row, so the restarted process's TryAcquire would lose to its
  # own dead predecessor's still-unexpired lease and silently skip every
  # scan for ~2 hours. Deleting the row here is fixture-only DB surgery
  # standing in for "wait out the TTL" (real ops would eventually recover
  # the same way); it does not touch hub code or weaken anything the hub
  # itself checks.
  sqlite3 "$HUB_DIR/data/kryptkeeper.db" "DELETE FROM ha_scheduler_locks WHERE lock_name='renewal-scheduler';" 2>/dev/null || true
  start_hub
  PASS "hub restarted, answering again on $HUB_BASE"

  STEP "[sweep] Mailpit receives a renewal reminder addressed to the cert owner"
  found="$(poll_json "http://127.0.0.1:${MAILPIT_HTTP_PORT}/api/v1/messages" "
import json,sys
d=json.load(sys.stdin)
for m in d.get('messages', []):
    if m['To'][0]['Address'] == '$SWEEP_OWNER':
        print(m['ID'])
        break
" 20)"
  if [ -n "$found" ]; then
    body="$(curl -sS "http://127.0.0.1:${MAILPIT_HTTP_PORT}/api/v1/message/${found}")"
    if echo "$body" | python3 -c "import json,sys; d=json.load(sys.stdin); sys.exit(0 if 'renewal reminder' in d.get('Text','') and 'kk-uat-sweep.local' in d.get('Text','') else 1)"; then
      PASS "[sweep] REAL expiry-sweep trigger delivered a renewal reminder to $SWEEP_OWNER (message $found)"
    else
      FAIL "[sweep] message $found to $SWEEP_OWNER found but body doesn't look like the scheduler's renewal reminder"
    fi
  else
    FAIL "[sweep] no renewal-reminder email to $SWEEP_OWNER appeared within 20s of hub restart (see $WORK/hub.log)"
  fi
else
  FAIL "[sweep] skipped -- no certificate issued to test the real trigger against"
fi

STEP "result"
if [ "$FAILED" -eq 0 ]; then
  echo "ALL PASS"
  exit 0
else
  echo "ONE OR MORE STEPS FAILED (see FAIL lines above; hub log: $WORK/hub.log, echo log: $ECHO_LOG kept until cleanup)"
  exit 1
fi
