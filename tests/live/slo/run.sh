#!/usr/bin/env bash
# W30-19: SLO breach drill against a REAL Prometheus and Grafana.
#
# Proves: (1) an idle estate does not page, (2) a forced renewal-success-rate
# breach pages EXACTLY ONCE through the notification fan-out and a steady
# breach does not re-page, (3) the shipped docs/ops/pki-slo-dashboard.json
# imports into Grafana and its renewal panel expression returns data from
# Prometheus (directly and through Grafana's datasource proxy).
#
#   bash tests/live/slo/run.sh
#
# Needs: podman, curl, python3, openssl, ssh-keygen, go, and the two images
# below already pulled (or a registry route): docker.io/prom/prometheus and
# docker.io/grafana/grafana-oss. No operator credentials are involved; the
# Grafana admin password is generated per run and never printed.
#
# KK_SLO_NO_OBS=1 runs only the hub half (steps 1, 3-5: hub + echo receiver,
# idle check, forced breach, exactly-once). Prometheus/Grafana steps (2, 6)
# are then reported SKIPPED -- use it where the images are unavailable. It
# does NOT satisfy acceptance 2 (that needs the dashboard series).
#
# Single-channel on purpose: after W30-04 SLO alerts fan out to every
# configured channel, so WEBHOOK_URL is the ONLY channel configured here and
# "exactly once" is unambiguous.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib/podman.sh"
set -u
set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/kk-uat-slo.XXXXXX")"
RUN_ID="$(openssl rand -hex 3)"
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
HUB_PORT="$(free_port)"
ECHO_PORT="$(free_port)"
# The hub egress guard (internal/egress, docs/ops/EGRESS.md) ALWAYS refuses
# loopback, so the webhook receiver must sit on a private (RFC1918) address of
# this host, not 127.0.0.1. Override with KK_SLO_ECHO_HOST.
ECHO_HOST="${KK_SLO_ECHO_HOST:-$(python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("10.255.255.255", 1)); print(s.getsockname()[0])' 2>/dev/null)}"
PROM_PORT="$(free_port)"
GRAF_PORT="$(free_port)"
HUB_BASE="http://127.0.0.1:${HUB_PORT}"
TOKEN="uat-token-${RUN_ID}"
PROM_IMAGE="${KK_SLO_PROM_IMAGE:-docker.io/prom/prometheus:v2.55.1}"
GRAF_IMAGE="${KK_SLO_GRAFANA_IMAGE:-docker.io/grafana/grafana-oss:11.3.0}"
PROM_CTR="kk-uat-slo-prom-$RUN_ID"
GRAF_CTR="kk-uat-slo-graf-$RUN_ID"
NET="kk-uat-slo-net-$RUN_ID"
NO_OBS="${KK_SLO_NO_OBS:-}"
SWEEP_MINUTES=1
ECHO_LOG="$WORK/echo-requests.jsonl"
DASHBOARD_JSON="$REPO_ROOT/docs/ops/pki-slo-dashboard.json"
HUB_BIN="$WORK/kryptkeeper"

FAILED=0
STEP() { echo; echo "== $* =="; }
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }
SKIP() { echo "SKIP: $*"; }
DIE()  { echo "FAIL: $*"; exit 1; }

HUB_PID=""
ECHO_PID=""
cleanup() {
  STEP "cleanup"
  [ -n "$HUB_PID" ] && kill "$HUB_PID" 2>/dev/null || true
  [ -n "$ECHO_PID" ] && kill "$ECHO_PID" 2>/dev/null || true
  kk_rm "$PROM_CTR" "$GRAF_CTR"
  podman network rm "$NET" >/dev/null 2>&1 || true
  if [ -n "${KK_UAT_KEEP:-}" ]; then
    echo "KK_UAT_KEEP set -- leaving $WORK in place"
  else
    rm -rf "$WORK"
  fi
}
trap cleanup EXIT

curlj() { curl -sS -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' "$@"; }
jget() { python3 -c "import json,sys
d=json.load(sys.stdin)
for k in sys.argv[1].split('.'):
    d=d[int(k)] if isinstance(d, list) else d[k]
print(d)" "$1" 2>/dev/null; }

# echo_count <path> [needle]: records the receiver logged for path whose
# body contains needle (default: any).
echo_count() {
  python3 -c "
import json, sys
path, needle, n = sys.argv[1], sys.argv[2], 0
try:
    with open(sys.argv[3]) as f:
        for line in f:
            rec = json.loads(line)
            if rec['path'] == path and needle in rec['body']:
                n += 1
except FileNotFoundError:
    pass
print(n)" "$1" "${2:-}" "$ECHO_LOG"
}

# ---------------------------------------------------------------------------
# 0. Preconditions.
# ---------------------------------------------------------------------------
STEP "preconditions"
for bin in podman curl python3 openssl ssh-keygen go; do
  command -v "$bin" >/dev/null 2>&1 || DIE "required tool not found: $bin"
done
case "$ECHO_HOST" in
  10.*|192.168.*|172.1[6-9].*|172.2?.*|172.3[01].*) ;;
  *) DIE "no private (RFC1918) host address found for the echo receiver (got '${ECHO_HOST}'); set KK_SLO_ECHO_HOST" ;;
esac
[ -f "$DASHBOARD_JSON" ] || DIE "missing $DASHBOARD_JSON"
if [ -z "$NO_OBS" ]; then
  for img in "$PROM_IMAGE" "$GRAF_IMAGE"; do
    podman image exists "$img" || DIE "image not present locally: $img (podman pull it first, or set KK_SLO_NO_OBS=1 for the hub-only half)"
  done
fi
PASS "tools and images present"

# ---------------------------------------------------------------------------
# 1. Receiver + hub (webhook is the ONLY channel; chans[0]).
# ---------------------------------------------------------------------------
STEP "start echo receiver and hub"
: >"$ECHO_LOG"
python3 "$REPO_ROOT/tests/live/notifications/echo_receiver.py" "$ECHO_LOG" "$ECHO_PORT" "$ECHO_HOST" >"$WORK/echo.log" 2>&1 &
ECHO_PID=$!
( cd "$REPO_ROOT" && go build -o "$HUB_BIN" ./cmd/kryptkeeper ) || DIE "go build failed"
mkdir -p "$WORK/data"
(
  export APP_BOOTSTRAP_TOKEN="$TOKEN" AUTH_MODE=bootstrap APP_CERTIFICATE_PROVIDER=ca \
    KRYPTKEEPER_TLS_DISABLE=true APP_DISCOVERY_PROVIDER=db APP_NOTIFICATION_PROVIDER=delivery \
    APP_CREDENTIAL_STORE_PASSPHRASE='uat-cred-passphrase-32-bytes-long!!' \
    KRYPTKEEPER_KEYSTORE_PASSPHRASE='uat-keystore-passphrase-32-bytes!!' \
    KRYPTKEEPER_DATA_DIR="$WORK/data" APP_CA_FILE="$WORK/data/cas.json" \
    APP_TEMPLATE_FILE="$WORK/data/templates.json" APP_CERTIFICATE_FILE="$WORK/data/certificates.json" \
    APP_AUDIT_FILE="$WORK/data/audit.json" APP_CERTS_SUMMARY_FILE="$WORK/data/certs_summary.json" \
    KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true KRYPTKEEPER_CA_NAME="UAT Root CA" \
    APP_BIND_ADDR=0.0.0.0 PORT="$HUB_PORT" \
    KRYPTKEEPER_SLO_SWEEP_MINUTES="$SWEEP_MINUTES" KRYPTKEEPER_SLO_NOTIFY_TARGET=slo-drill \
    WEBHOOK_URL="http://${ECHO_HOST}:${ECHO_PORT}/slo"
  unset SLACK_WEBHOOK_URL PAGERDUTY_ROUTING_KEY SMTP_HOST SIEM_WEBHOOK_URL
  exec "$HUB_BIN" >"$WORK/hub.log" 2>&1
) &
HUB_PID=$!
tries=40
until curl -sS -f -o /dev/null "${HUB_BASE}/api/v1/cas" -H "Authorization: Bearer ${TOKEN}" 2>/dev/null; do
  tries=$((tries - 1)); [ $tries -le 0 ] && DIE "hub never answered, see $WORK/hub.log"
  sleep 1
done
tries=30
until curl -sS -f -o /dev/null "http://${ECHO_HOST}:${ECHO_PORT}/health" 2>/dev/null; do
  tries=$((tries - 1)); [ $tries -le 0 ] && DIE "echo receiver never answered"
  sleep 1
done
PASS "hub on :$HUB_PORT (sweep ${SWEEP_MINUTES}m), echo receiver on :$ECHO_PORT"

# ---------------------------------------------------------------------------
# 2. Prometheus + Grafana, dashboard import.
# ---------------------------------------------------------------------------
GRAF_PASS=""
GRAF_BASE="http://127.0.0.1:${GRAF_PORT}"
PROM_BASE="http://127.0.0.1:${PROM_PORT}"
if [ -z "$NO_OBS" ]; then
  STEP "start Prometheus (scrape host.containers.internal:${HUB_PORT}/metrics every 5s) and Grafana"
  cat >"$WORK/prometheus.yml" <<EOF
global:
  scrape_interval: 5s
scrape_configs:
  - job_name: kryptkeeper
    metrics_path: /metrics
    static_configs:
      - targets: ["host.containers.internal:${HUB_PORT}"]
EOF
  # Own network so Grafana reaches Prometheus by container name (a loopback-
  # published port is not reachable via host.containers.internal on a podman VM).
  podman network create "$NET" >/dev/null || DIE "network create failed"
  podman run -d --name "$PROM_CTR" --network "$NET" -p "127.0.0.1:${PROM_PORT}:9090" \
    -v "$WORK/prometheus.yml:/etc/prometheus/prometheus.yml:ro" "$PROM_IMAGE" >/dev/null \
    && PASS "prometheus container up" || DIE "prometheus failed to start"
  GRAF_PASS="$(openssl rand -hex 16)"
  # Passed by name so the value never appears on a command line.
  export GF_SECURITY_ADMIN_PASSWORD="$GRAF_PASS" GF_AUTH_ANONYMOUS_ENABLED=false
  podman run -d --name "$GRAF_CTR" --network "$NET" -p "127.0.0.1:${GRAF_PORT}:3000" \
    -e GF_SECURITY_ADMIN_PASSWORD -e GF_AUTH_ANONYMOUS_ENABLED "$GRAF_IMAGE" >/dev/null \
    && PASS "grafana container up (admin password generated, not printed)" || DIE "grafana failed to start"
  gcurl() { curl -sS -u "admin:${GRAF_PASS}" -H 'Content-Type: application/json' "$@"; }
  tries=60
  until curl -sS -f -o /dev/null "${GRAF_BASE}/api/health" 2>/dev/null; do
    tries=$((tries - 1)); [ $tries -le 0 ] && DIE "grafana never became healthy"
    sleep 2
  done
  tries=60
  until curl -sS -f -o /dev/null "${PROM_BASE}/-/ready" 2>/dev/null; do
    tries=$((tries - 1)); [ $tries -le 0 ] && DIE "prometheus never became ready"
    sleep 2
  done
  # Prometheus reaches the hub from inside its own container; confirm it scrapes it.
  tries=40
  until curl -sS "${PROM_BASE}/api/v1/query?query=up%7Bjob%3D%22kryptkeeper%22%7D" | grep -q '"1"\]'; do
    tries=$((tries - 1)); [ $tries -le 0 ] && DIE "prometheus never scraped the hub (host.containers.internal:${HUB_PORT}); check the podman machine's host networking"
    sleep 2
  done
  PASS "prometheus scraping the hub (up==1)"

  STEP "provision default Prometheus datasource and import pki-slo-dashboard.json"
  ds_resp="$(gcurl -X POST "${GRAF_BASE}/api/datasources" -d "$(python3 -c "import json,sys; print(json.dumps({'name':'prometheus','type':'prometheus','access':'proxy','url':'http://${PROM_CTR}:9090','isDefault':True}))")")"
  DS_UID="$(echo "$ds_resp" | jget datasource.uid)"
  [ -n "$DS_UID" ] && PASS "datasource uid=$DS_UID (default)" || DIE "datasource create failed: $ds_resp"
  dash_resp="$(gcurl -X POST "${GRAF_BASE}/api/dashboards/db" -d "$(python3 -c "
import json,sys
print(json.dumps({'dashboard': json.load(open(sys.argv[1])), 'overwrite': True}))" "$DASHBOARD_JSON")")"
  [ "$(echo "$dash_resp" | jget status)" = "success" ] && PASS "dashboard imported" || FAIL "dashboard import failed: $dash_resp"
else
  STEP "Prometheus / Grafana"
  SKIP "KK_SLO_NO_OBS=1 -- datasource + dashboard import not exercised"
fi

# ---------------------------------------------------------------------------
# 3. Idle check: 2 sweep intervals, zero pages.
# ---------------------------------------------------------------------------
STEP "idle estate must not page (waiting 2 sweep intervals = $((2 * SWEEP_MINUTES * 60 + 10))s)"
sleep $((2 * SWEEP_MINUTES * 60 + 10))
n="$(echo_count /slo)"
[ "$n" = "0" ] && PASS "0 records at /slo while idle" || FAIL "idle estate paged: $n record(s) at /slo"

# ---------------------------------------------------------------------------
# 4. Force the breach: 5 failed renewal/execute calls against a closed port.
#    Every failure increments kryptkeeper_cert_renewal_failure_total; success
#    stays 0 so the renewal-success-rate is 0 < 99%.
# ---------------------------------------------------------------------------
STEP "force breach: ssh target at 127.0.0.1:1 + renewal/execute x6"
CA_ID="$(curlj "${HUB_BASE}/api/v1/cas" | jget data.0.id)"
[ -n "$CA_ID" ] || DIE "no CA found"
ssh-keygen -q -t ed25519 -N '' -f "$WORK/id_ed25519" -C kk-uat-slo || DIE "ssh-keygen failed"
ssh-keygen -q -t ed25519 -N '' -f "$WORK/hostkey" -C kk-uat-slo-host || DIE "ssh-keygen failed"
cred_body="$(python3 -c "
import json,sys
print(json.dumps({'name':'uat-slo-ssh','credential_type':'ssh_key','payload':{
  'user':'root','private_key_pem':open(sys.argv[1]).read(),
  'host_public_key':open(sys.argv[2]).read().strip(),'port':1}}))" "$WORK/id_ed25519" "$WORK/hostkey.pub")"
cred_resp="$(curlj -X POST "${HUB_BASE}/api/v1/credentials" -d "$cred_body")"
CRED_ID="$(echo "$cred_resp" | jget data.id)"
[ -n "$CRED_ID" ] && PASS "throwaway credential: $CRED_ID" || DIE "credential create failed: $cred_resp"
target_resp="$(curlj -X POST "${HUB_BASE}/api/v1/targets" -d "$(python3 -c "
import json,sys
print(json.dumps({'host':'127.0.0.1','discovery_mode':'network','install_mode':'ssh','credential_ref':sys.argv[1],
  'install_server_type':'nginx','install_cert_path':'/etc/ssl/kk/server.crt','install_key_path':'/etc/ssl/kk/server.key',
  'install_reload_method':'binary','name':'kk-slo-drill.local'}))" "$CRED_ID")")"
TARGET_ID="$(echo "$target_resp" | jget data.id)"
[ -n "$TARGET_ID" ] && PASS "closed-port target: $TARGET_ID" || DIE "target create failed: $target_resp"

tpl_resp="$(curlj -X POST "${HUB_BASE}/api/v1/templates" -d '{"name":"uat-slo","display_name":"UAT SLO drill","allowed_algorithms":["ECDSA"],"key_usage":["digitalSignature","keyEncipherment"],"extended_key_usage":["serverAuth"],"validity_period":"2160h","active":true}')"
TPL_ID="$(echo "$tpl_resp" | jget data.id)"
[ -n "$TPL_ID" ] || DIE "template create failed: $tpl_resp"
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$WORK/c.key" -out "$WORK/c.csr" \
  -subj "/CN=kk-slo-drill.local" -addext "subjectAltName=DNS:kk-slo-drill.local" >/dev/null 2>&1
issue_resp="$(curlj -X POST "${HUB_BASE}/api/v1/certificates" -d "$(python3 -c "
import json,sys
print(json.dumps({'ca_id':sys.argv[1],'template_id':sys.argv[2],'csr_pem':open(sys.argv[3]).read()}))" "$CA_ID" "$TPL_ID" "$WORK/c.csr")")"
FP="$(echo "$issue_resp" | jget data.fingerprint_sha256)"
[ -n "$FP" ] && PASS "certificate to renew: $FP" || DIE "issue failed: $issue_resp"

# Call #1 renews the certificate (a successor is minted) and then FAILS to
# install over SSH (connect_failed): the executor counts that as a renewal
# success (renewal_executor.go defers on result.Renewed), so success_total is 1.
# Calls #2..#6 hit "certificate already has a successor" (HTTP 409, err != nil)
# and each increments failure_total. Result: 1 success vs 5 failures, rate
# 0.17 < 0.99. (Spec text assumed success stays 0; the code does not work that
# way, so the drill primes once and then fails five times.)
for i in 1 2 3 4 5 6; do
  code="$(curlj -o "$WORK/exec-$i.json" -w '%{http_code}' -X POST "${HUB_BASE}/api/v1/renewal/execute" -d "$(python3 -c "
import json,sys
print(json.dumps({'fingerprint':sys.argv[1],'target_id':sys.argv[2]}))" "$FP" "$TARGET_ID")")"
  echo "  renewal/execute #$i -> HTTP $code"
done
# The counters are the contract, not the HTTP codes: read them back.
fails="$(curl -sS "${HUB_BASE}/metrics" | awk '/^kryptkeeper_cert_renewal_failure_total/ {print $2}')"
succ="$(curl -sS "${HUB_BASE}/metrics" | awk '/^kryptkeeper_cert_renewal_success_total/ {print $2}')"
echo "  kryptkeeper_cert_renewal_failure_total=${fails:-?} kryptkeeper_cert_renewal_success_total=${succ:-?}"
if python3 -c "
import sys
f, s = float(sys.argv[1]), float(sys.argv[2])
sys.exit(0 if f >= 5 and s / (s + f) < 0.99 else 1)" "${fails:-0}" "${succ:-0}" 2>/dev/null; then
  PASS "failure_total=${fails} success_total=${succ}: renewal success rate below the 99% objective"
else
  FAIL "counters do not describe a breach (failure=${fails:-?} success=${succ:-?}); see $WORK/exec-*.json"
fi

# ---------------------------------------------------------------------------
# 5. Exactly one page within 150 s; steady breach must not re-page.
# ---------------------------------------------------------------------------
STEP "exactly one page at /slo mentioning renewal-success-rate (<=150s)"
tries=150
n=0
while [ "$tries" -gt 0 ]; do
  n="$(echo_count /slo renewal-success-rate)"
  [ "$n" -ge 1 ] && break
  sleep 1; tries=$((tries - 1))
done
[ "$n" = "1" ] && PASS "1 record at /slo mentioning renewal-success-rate" || FAIL "expected 1 record, saw $n"

STEP "steady breach does not re-page (3 more sweeps = $((3 * SWEEP_MINUTES * 60 + 10))s)"
sleep $((3 * SWEEP_MINUTES * 60 + 10))
n="$(echo_count /slo)"
[ "$n" = "1" ] && PASS "still exactly 1 record at /slo" || FAIL "expected exactly 1 record at /slo after steady breach, saw $n"

# ---------------------------------------------------------------------------
# 6. Series check: Prometheus direct, Grafana datasource query, dashboard uid.
# ---------------------------------------------------------------------------
if [ -z "$NO_OBS" ]; then
  STEP "renewal panel expression returns a series (Prometheus + Grafana) and dashboard uid exists"
  EXPR="$(python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
for p in d['panels']:
    if p['title'].startswith('Renewal success rate'):
        print(p['targets'][0]['expr']); break" "$DASHBOARD_JSON")"
  DASH_UID="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['uid'])" "$DASHBOARD_JSON")"
  [ -n "$EXPR" ] || DIE "renewal panel expression not found in the dashboard JSON"
  enc="$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$EXPR")"
  tries=30; plen=0
  while [ "$tries" -gt 0 ]; do
    plen="$(curl -sS "${PROM_BASE}/api/v1/query?query=${enc}" | python3 -c "import json,sys; print(len(json.load(sys.stdin)['data']['result']))" 2>/dev/null)"
    [ "${plen:-0}" -ge 1 ] && break
    sleep 5; tries=$((tries - 1))
  done
  [ "${plen:-0}" -ge 1 ] && PASS "prometheus: renewal expression returns $plen series" || FAIL "prometheus: renewal expression empty"
  now_ms="$(python3 -c 'import time; print(int(time.time()*1000))')"
  q_resp="$(gcurl -X POST "${GRAF_BASE}/api/ds/query" -d "$(python3 -c "
import json,sys
print(json.dumps({'queries':[{'refId':'A','datasource':{'uid':sys.argv[1],'type':'prometheus'},'expr':sys.argv[2],'instant':True}],
  'from':str(int(sys.argv[3])-600000),'to':sys.argv[3]}))" "$DS_UID" "$EXPR" "$now_ms")")"
  frames="$(echo "$q_resp" | python3 -c "import json,sys; print(len(json.load(sys.stdin)['results']['A']['frames']))" 2>/dev/null)"
  [ "${frames:-0}" -ge 1 ] && PASS "grafana /api/ds/query: $frames frame(s)" || FAIL "grafana /api/ds/query returned no frames"
  guid="$(gcurl "${GRAF_BASE}/api/dashboards/uid/${DASH_UID}" | python3 -c "import json,sys; print(json.load(sys.stdin)['dashboard']['uid'])" 2>/dev/null)"
  [ "$guid" = "$DASH_UID" ] && PASS "dashboard uid $DASH_UID exists in grafana" || FAIL "dashboard uid $DASH_UID not found in grafana"
else
  STEP "series check"
  SKIP "KK_SLO_NO_OBS=1 -- Prometheus/Grafana series not checked (acceptance 2 NOT satisfied by this run)"
fi

STEP "result"
if [ "$FAILED" -eq 0 ]; then
  echo "ALL PASS"
  exit 0
fi
echo "ONE OR MORE STEPS FAILED (hub log: $WORK/hub.log; rerun with KK_UAT_KEEP=1 to keep it)"
exit 1
