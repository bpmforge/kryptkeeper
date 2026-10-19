#!/usr/bin/env bash
# W22-08: live SIEM UAT. Real receivers (Elasticsearch, syslog-ng) under
# podman; the hub forwards one audit event per phase and each form must land
# within 5 s. No product code is touched: a defect found here is reported.
#
#   phase 1  SIEM_FORMAT=json  webhook -> Elasticsearch, syslog(tcp) -> syslog-ng
#   phase 2  SIEM_FORMAT=cef   syslog(tcp) -> syslog-ng (no webhook: the CEF body
#                              is text/plain and Elasticsearch would reject it)
#   phase 3  json again; kill both receivers, assert the failure counter rises
#            and the audit rows survive.
#
# Splunk HEC is NOT exercised (see README.md).
set -u
set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"

PODMAN="$(command -v podman || true)"
[ -z "$PODMAN" ] && [ -x /opt/homebrew/bin/podman ] && PODMAN=/opt/homebrew/bin/podman
if [ -z "$PODMAN" ]; then
  if [ -n "${KK_UAT_REQUIRE:-}" ]; then echo "FAIL: podman not found and KK_UAT_REQUIRE is set"; exit 1; fi
  echo "[siem-uat] SKIP: podman not found (set KK_UAT_REQUIRE=1 to make this a failure)"; exit 0
fi

ES_IMAGE=docker.io/elastic/elasticsearch:8.15.3
# linuxserver/syslog-ng is multi-arch; balabit/syslog-ng:4.8.0 is amd64-only and
# segfaults under qemu emulation on Apple Silicon podman machines.
SYSLOG_IMAGE=docker.io/linuxserver/syslog-ng:4.11.0-r0-ls211
TOKEN=uat-token # throwaway bootstrap token for the throwaway hub below
BUDGET=5.0

# podman on macOS only bind-mounts under /Users, so the working dir lives in $HOME.
WORK="$(mktemp -d "$HOME/.kk-w22-siem.XXXXXX")"
LOGDIR="$WORK/syslog"
mkdir -p "$LOGDIR" "$WORK/hub/data"
chmod 777 "$LOGDIR"
: >"$LOGDIR/in.log"; chmod 666 "$LOGDIR/in.log"

free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
HUB_PORT="$(free_port)"; ES_PORT="$(free_port)"; SYS_PORT="$(free_port)"
HUB="http://127.0.0.1:${HUB_PORT}"
# The hub's egress guard refuses loopback webhook destinations unless a Go test
# seam (egressAllowLoopback) is set, so a 127.0.0.1 Elastic URL can never be
# delivered to (reported as a finding, see README). Private (RFC1918) space is
# allowed, so Elasticsearch is published on this host's private address only.
HOST_IP="${KK_SIEM_HOST_IP:-$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}')}"
if [ -z "$HOST_IP" ]; then echo "FAIL: no private host IP found for the webhook receiver (set KK_SIEM_HOST_IP)"; exit 1; fi
ES="http://${HOST_IP}:${ES_PORT}"
RUN_ID="$RANDOM$RANDOM"
ES_CTR="kk-w22-siem-es-$RUN_ID"
SYS_CTR="kk-w22-siem-syslog-$RUN_ID"

PASS_N=0; FAIL_N=0
STEP() { echo; echo "== $* =="; }
PASS() { echo "PASS: $*"; PASS_N=$((PASS_N + 1)); }
FAIL() { echo "FAIL: $*"; FAIL_N=$((FAIL_N + 1)); }
now() { python3 -c 'import time; print(time.time())'; }
elapsed() { python3 -c "import time; print('%.2f' % (time.time() - $1))"; }

HUB_PID=""
stop_hub() {
  [ -n "$HUB_PID" ] && kill "$HUB_PID" 2>/dev/null || true
  [ -n "$HUB_PID" ] && wait "$HUB_PID" 2>/dev/null || true
  HUB_PID=""
}
cleanup() {
  STEP "cleanup"
  stop_hub
  # one rm per name: podman 4.9 removes nothing if any listed name is missing
  "$PODMAN" rm -f -t 0 "$ES_CTR" >/dev/null 2>&1 || true
  "$PODMAN" rm -f -t 0 "$SYS_CTR" >/dev/null 2>&1 || true
  if [ -n "${KK_UAT_KEEP:-}" ]; then echo "KK_UAT_KEEP set -- leaving $WORK"; else rm -rf "$WORK"; fi
}
summary() {
  echo; echo "[siem-uat] PASS=$PASS_N FAIL=$FAIL_N"
  [ "$FAIL_N" -eq 0 ]
}
DIE() { FAIL "$*"; cleanup; trap - EXIT; summary; exit 1; }
trap cleanup EXIT

curlj() { curl -sS -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' "$@"; }

# wait_for <deadline_s> <cmd...>: poll every 0.2 s; sets WAITED to the seconds
# since T0 on success. The budget includes the hub's async queue.
WAITED=""
wait_for() {
  local deadline=$1; shift
  while :; do
    if "$@" >/dev/null 2>&1; then WAITED="$(elapsed "$T0")"; return 0; fi
    python3 -c "import sys,time; sys.exit(0 if time.time()-$T0 < $deadline else 1)" || return 1
    sleep 0.2
  done
}
within_budget() { python3 -c "import sys; sys.exit(0 if $1 <= $BUDGET else 1)"; }

es_has_marker() {
  curl -sS -X POST "${ES}/siem-uat/_refresh" >/dev/null 2>&1
  curl -sS "${ES}/siem-uat/_search?q=resource_id:%22${MARK}%22" | python3 -c '
import json, sys
m = sys.argv[1]
hits = json.load(sys.stdin)["hits"]["hits"]
src = [h["_source"] for h in hits if h["_source"].get("resource_id") == m]
ok = len(src) == 1 and src[0].get("event_type") == "role.create" and src[0].get("resource_type") == "role" \
     and src[0].get("severity") and src[0].get("timestamp")
sys.exit(0 if ok else 1)' "$MARK"
}
# After the msgid the hub emits STRUCTURED-DATA: "-" in cef form, "[kryptkeeper@99999 ...]"
# in json form (the spec's literal "- " after msgid only matches the cef form).
HDR_RE='^([0-9]+ )?<[0-9]+>1 [0-9T:.+-]+Z? [^ ]+ kryptkeeper - role_create (-|\[kryptkeeper@99999 )'
# The collector may emit a bare line (framing stripped) or keep the octet count.
syslog_line() { grep -F -- "$MARK" "$LOGDIR/in.log" | tail -1; }
syslog_has_header() { syslog_line | grep -Eq -- "$HDR_RE"; }
syslog_has_cef() { syslog_line | grep -Eq -- 'CEF:0\|'; }

trigger() { # sets MARK and T0, posts one role.create
  MARK="siem-uat-$RANDOM$RANDOM"
  T0="$(now)"
  local code
  code="$(curlj -o /dev/null -w '%{http_code}' -X POST "$HUB/api/v1/roles" -d '{"name":"'"$MARK"'","permissions":["certificate.read"]}')"
  [ "$code" = "201" ] || DIE "role.create trigger returned HTTP $code (expected 201)"
}

# ---------------------------------------------------------------------------
STEP "build hub"
( cd "$REPO_ROOT" && go build -o "$WORK/hub/kryptkeeper" ./cmd/kryptkeeper ) && PASS "hub built" || DIE "go build failed"

hub_env() { # $1 = format, $2 = with_webhook(1/0)
  export APP_BOOTSTRAP_TOKEN="$TOKEN" AUTH_MODE=bootstrap APP_CERTIFICATE_PROVIDER=ca \
    KRYPTKEEPER_TLS_DISABLE=true APP_DISCOVERY_PROVIDER=db \
    APP_CREDENTIAL_STORE_PASSPHRASE='uat-cred-passphrase-32-bytes-long!!' \
    KRYPTKEEPER_KEYSTORE_PASSPHRASE='uat-keystore-passphrase-32-bytes!!' \
    KRYPTKEEPER_DATA_DIR="$WORK/hub/data" \
    APP_CA_FILE="$WORK/hub/data/cas.json" APP_TEMPLATE_FILE="$WORK/hub/data/templates.json" \
    APP_CERTIFICATE_FILE="$WORK/hub/data/certificates.json" APP_AUDIT_FILE="$WORK/hub/data/audit.json" \
    APP_CERTS_SUMMARY_FILE="$WORK/hub/data/certs_summary.json" \
    KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true KRYPTKEEPER_CA_NAME="UAT Root CA" \
    APP_BIND_ADDR=127.0.0.1 PORT="$HUB_PORT" \
    SIEM_FORMAT="$1" SIEM_SYSLOG_ADDR="127.0.0.1:${SYS_PORT}" SIEM_SYSLOG_PROTO=tcp
  if [ "$2" = 1 ]; then export SIEM_WEBHOOK_URL="${ES_WEBHOOK_BASE}/siem-uat/_doc"; else unset SIEM_WEBHOOK_URL; fi
  unset SIEM_WEBHOOK_TOKEN KRYPTKEEPER_SIEM_ACTIONS
}
start_hub() { # $1 = format, $2 = with_webhook
  stop_hub
  ( hub_env "$1" "$2"; exec "$WORK/hub/kryptkeeper" ) >>"$WORK/hub.log" 2>&1 &
  HUB_PID=$!
  local tries=120 # a cold hub needs ~10 s idle, far longer on a busy runner
  until curl -sS -f -o /dev/null "$HUB/api/v1/cas" -H "Authorization: Bearer ${TOKEN}" 2>/dev/null; do
    tries=$((tries - 1)); [ $tries -le 0 ] && DIE "hub never answered, see $WORK/hub.log"
    sleep 1
  done
}

# ---------------------------------------------------------------------------
STEP "start Elasticsearch ($ES_IMAGE) on ${HOST_IP}:${ES_PORT}"
"$PODMAN" run -d --name "$ES_CTR" -p "${HOST_IP}:${ES_PORT}:9200" \
  -e discovery.type=single-node -e xpack.security.enabled=false -e 'ES_JAVA_OPTS=-Xms512m -Xmx512m' \
  "$ES_IMAGE" >/dev/null && PASS "elasticsearch container $ES_CTR started" || DIE "could not start elasticsearch"
ES_WEBHOOK_BASE="$ES"

STEP "start syslog-ng ($SYSLOG_IMAGE) on 127.0.0.1:${SYS_PORT}"
cat >"$WORK/syslog-ng.conf" <<'CONF'
@version: 4.11
# syslog() on tcp understands RFC 6587 octet-counted frames, which is what the
# hub sends. store-raw-message keeps the original text for the %RAWMSG line.
source s_in { syslog(ip(0.0.0.0) port(5514) transport("tcp") flags(store-raw-message)); };
destination d_raw { file("/var/log/uat/in.log" template("${RAWMSG}\n") perm(0666)); };
log { source(s_in); destination(d_raw); };
CONF
"$PODMAN" run -d --name "$SYS_CTR" -p "127.0.0.1:${SYS_PORT}:5514" \
  -e PUID=0 -e PGID=0 -v "$WORK/syslog-ng.conf:/config/syslog-ng.conf:ro" -v "$LOGDIR:/var/log/uat" \
  "$SYSLOG_IMAGE" >/dev/null && PASS "syslog-ng container $SYS_CTR started" || DIE "could not start syslog-ng"

STEP "wait for Elasticsearch (<=120 s)"
tries=120
until curl -sS -f -o /dev/null "${ES}/_cluster/health?wait_for_status=yellow&timeout=1s" 2>/dev/null; do
  tries=$((tries - 1))
  if [ $tries -le 0 ]; then "$PODMAN" logs --tail 30 "$ES_CTR" 2>&1 | tail -30; DIE "elasticsearch never became healthy"; fi
  sleep 1
done
PASS "elasticsearch cluster health >= yellow"

STEP "wait for syslog-ng to accept connections"
tries=30
until python3 -c "import socket; socket.create_connection(('127.0.0.1',${SYS_PORT}),1).close()" 2>/dev/null; do
  tries=$((tries - 1))
  if [ $tries -le 0 ]; then "$PODMAN" logs --tail 30 "$SYS_CTR" 2>&1 | tail -30; DIE "syslog-ng never accepted a connection"; fi
  sleep 1
done
PASS "syslog-ng listening"

# ---------------------------------------------------------------------------
STEP "phase 1: SIEM_FORMAT=json, webhook -> Elasticsearch, syslog -> syslog-ng"
start_hub json 1
trigger
# One loop watches both receivers so each latency is the true first-seen time
# from T0, not inflated by waiting on the other receiver first.
T_ES=""; T_SYS=""
while :; do
  [ -z "$T_ES" ] && es_has_marker >/dev/null 2>&1 && T_ES="$(elapsed "$T0")"
  [ -z "$T_SYS" ] && syslog_has_header >/dev/null 2>&1 && T_SYS="$(elapsed "$T0")"
  { [ -n "$T_ES" ] && [ -n "$T_SYS" ]; } && break
  python3 -c "import sys,time; sys.exit(0 if time.time()-$T0 < $BUDGET + 25 else 1)" || break
  sleep 0.2
done
if [ -n "$T_ES" ] && within_budget "$T_ES"; then PASS "[siem] json/elastic arrived in ${T_ES}s (<= ${BUDGET}s)"
elif [ -n "$T_ES" ]; then FAIL "[siem] json/elastic arrived in ${T_ES}s (> ${BUDGET}s)"
else
  FAIL "[siem] json/elastic: no valid doc for $MARK within $((${BUDGET%.*} + 25))s"
  echo "  search response: $(curl -sS "${ES}/siem-uat/_search?q=resource_id:%22${MARK}%22" | cut -c1-600)"
fi
if [ -n "$T_SYS" ] && within_budget "$T_SYS"; then PASS "[siem] json/syslog RFC5424 arrived in ${T_SYS}s (<= ${BUDGET}s)"; echo "  line: $(syslog_line | cut -c1-200)"
elif [ -n "$T_SYS" ]; then FAIL "[siem] json/syslog arrived in ${T_SYS}s (> ${BUDGET}s)"
else FAIL "[siem] json/syslog: no RFC 5424 line for $MARK within ${BUDGET}s"; fi

STEP "phase 2: SIEM_FORMAT=cef, syslog -> syslog-ng (no webhook)"
start_hub cef 0
trigger
if wait_for $BUDGET syslog_has_cef; then
  within_budget "$WAITED" && PASS "[siem] cef/syslog arrived in ${WAITED}s (<= ${BUDGET}s)" || FAIL "[siem] cef/syslog arrived in ${WAITED}s (> ${BUDGET}s)"
  echo "  line: $(syslog_line | cut -c1-200)"
else
  FAIL "[siem] cef/syslog: no CEF line for $MARK within ${BUDGET}s"
fi
if syslog_has_header; then PASS "[siem] cef line carries the RFC 5424 header (msgid role_create)"; else FAIL "[siem] cef line lacks the RFC 5424 header"; fi

# ---------------------------------------------------------------------------
STEP "phase 3: kill the receivers; failure is counted and the audit row remains"
start_hub json 1
fails() { curl -sS -H "Authorization: Bearer ${TOKEN}" "$HUB/metrics" | awk '/^kryptkeeper_siem_send_failures_total/{print $2}'; }
FAILS0="$(fails)"
[ -n "$FAILS0" ] && PASS "metrics serve kryptkeeper_siem_send_failures_total (baseline $FAILS0)" || DIE "kryptkeeper_siem_send_failures_total not on /metrics"
MARK_OK="$MARK"
"$PODMAN" rm -f "$ES_CTR" "$SYS_CTR" >/dev/null 2>&1 && PASS "receivers removed" || FAIL "could not remove receivers"
trigger
MARK_DEAD="$MARK"
ok=0
for _ in $(seq 1 75); do
  cur="$(fails)"
  if [ -n "$cur" ] && python3 -c "import sys; sys.exit(0 if float('$cur') > float('$FAILS0') else 1)"; then ok=1; break; fi
  sleep 0.2
done
[ $ok = 1 ] && PASS "failure counter rose ${FAILS0} -> ${cur} within 15s" || FAIL "failure counter did not rise within 15s (still ${cur:-unset})"
audit="$(curlj "$HUB/api/v1/audit?action=role.create&limit=200")"
echo "$audit" | grep -q -- "$MARK_DEAD" && PASS "audit row for the post-kill event ($MARK_DEAD) remains" || FAIL "audit row for $MARK_DEAD missing"
echo "$audit" | grep -q -- "$MARK_OK" && PASS "audit row for the pre-kill event ($MARK_OK) remains" || FAIL "audit row for $MARK_OK missing"

trap - EXIT
cleanup
summary
