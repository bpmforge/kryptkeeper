#!/usr/bin/env bash
# W25-17: the hub's self-issued listener certificate is re-issued (same CA)
# and a running agent keeps working without re-enrolling.
#
# Renewal trigger: the hub has no in-process renew hook (selfIssuedTLSCertificate
# runs at process start), so the harness stops the hub, deletes only
# <data>/tls/tls.{crt,key} from the persistent volume (CA + keystore + db
# untouched) and starts it again with the same env. The agent container is
# never restarted and the system clock is never touched.
#
# Topology (podman, private network): hub (kkhub-*), agent+nginx fixture
# (agenthost-*), and an nginx reverse proxy to the hub that verifies the hub's
# certificate against the hub CA. Every TLS check below verifies against
# the hub CA; nothing in this file turns verification off (asserted last).
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib/podman.sh"
set -u
set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
# shellcheck source=/dev/null
. "$HERE/../podman-host.sh"
AP="$ROOT/tests/live/autopilot"
AGENT_FIX="$ROOT/tests/live/agent"
WORK="$(mktemp -d /tmp/kk-uat-lr.XXXXXX)"
# podman machine on macOS only mounts $HOME, so files bind-mounted into
# containers live under it.
SHARE="$(mktemp -d "$HOME/.kk-uat-lr.XXXXXX")"
RUN_ID="$(openssl rand -hex 3)"
NET="kk-uat-lr-net-$RUN_ID"
VOL="kk-uat-lr-data-$RUN_ID"
HUB="kkhub-$RUN_ID"
AGENT="agenthost-$RUN_ID"
PROXY="kkproxy-$RUN_ID"
HUB_IMG="localhost/kk-uat-lr-hub:$RUN_ID"
BASE_IMG="localhost/kk-uat-lr-fixture-base:$RUN_ID"
AGENT_IMG="localhost/kk-uat-lr-fixture:$RUN_ID"
POLL=10
ENROLL_SECRET="uat-lr-enrollment-secret"
API_TOKEN="uat-lr-token"

free_port() { # free_port <lo> <hi>
  local p
  for _ in $(seq 1 200); do
    p=$(( $1 + RANDOM % ($2 - $1) ))
    python3 -c "import socket,sys; s=socket.socket(); s.bind(('127.0.0.1',$p)); s.close()" 2>/dev/null && { echo "$p"; return; }
  done
  return 1
}
HUB_PORT="$(free_port 20080 20400)"
PROXY_PORT="$(free_port 20401 20900)"

FAILED=0
STEP() { echo; echo "== $* =="; }
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }
now() { python3 -c 'import time; print(time.time())'; }

cleanup() {
  STEP "cleanup"
  kk_rm "$PROXY" "$AGENT" "$HUB"
  podman volume rm -f "$VOL" >/dev/null 2>&1
  podman network rm "$NET" >/dev/null 2>&1
  podman rmi -f "$HUB_IMG" "$BASE_IMG" "$AGENT_IMG" >/dev/null 2>&1
  rm -rf "$WORK" "$SHARE"
}
trap cleanup EXIT
DIE() { echo "FAIL: $*"; exit 1; }

hub_url="https://127.0.0.1:${HUB_PORT}"
CA="$SHARE/hub-ca.pem"

# leaf_serial: serial of the listener leaf as presented, verified against $CA.
leaf_serial() {
  openssl s_client -connect "127.0.0.1:${HUB_PORT}" -servername localhost -CAfile "$CA" \
    -verify_return_error -verify_hostname localhost </dev/null 2>/dev/null \
    | openssl x509 -noout -serial 2>/dev/null | cut -d= -f2
}
verify_ok() {
  openssl s_client -connect "127.0.0.1:${HUB_PORT}" -servername localhost -CAfile "$CA" \
    -verify_return_error -verify_hostname localhost </dev/null 2>&1 | grep -q "Verify return code: 0 (ok)"
}
ca_fp() { openssl x509 -in "$1" -noout -fingerprint -sha256 | cut -d= -f2; }
fetch_ca() { podman cp "$HUB:/data/tls/ca.pem" "$1" >/dev/null 2>&1 && [ -s "$1" ]; }
wait_ready() { # wait_ready <seconds>: /readyz against the hub CA
  for _ in $(seq 1 "$1"); do
    curl -fsS --max-time 2 --cacert "$CA" "$hub_url/readyz" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}
register_count() { # successful agent.register audit events (GET /api/v1/audit, data[])
  curl -fsS --cacert "$CA" -H "Authorization: Bearer $API_TOKEN" "$hub_url/api/v1/audit?action=agent.register&limit=200" 2>/dev/null \
    | python3 -c '
import json,sys
d=json.load(sys.stdin)
print(sum(1 for e in d.get("data",[]) if e.get("action")=="agent.register" and e.get("outcome")=="success"))'
}

STEP "build hub, healthcheck and agent for the podman machine arch"
GOARCH="$(kk_goarch)"
mkdir -p "$WORK/hubctx" "$WORK/agentctx"
for b in kryptkeeper healthcheck; do
  (cd "$ROOT" && GOOS=linux GOARCH="$GOARCH" CGO_ENABLED=0 go build -o "$WORK/hubctx/$b" "./cmd/$b") || DIE "go build ./cmd/$b"
done
(cd "$ROOT" && GOOS=linux GOARCH="$GOARCH" CGO_ENABLED=0 go build -o "$WORK/agentctx/kryptkeeper-agent" ./cmd/kryptkeeper-agent) || DIE "go build agent"
echo "commit $(cd "$ROOT" && git rev-parse --short HEAD) dirty=$(cd "$ROOT" && git status --porcelain cmd internal | wc -l | tr -d ' ') GOARCH=$GOARCH"
cat >"$WORK/hubctx/Containerfile" <<'CF'
FROM docker.io/library/ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY kryptkeeper healthcheck /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/kryptkeeper"]
CF
cp "$AGENT_FIX/Containerfile" "$AGENT_FIX/entrypoint.sh" "$AGENT_FIX/nginx-agent-uat.conf" "$WORK/agentctx/"
{ podman build -q -t "$HUB_IMG" "$WORK/hubctx" \
  && podman build -q -t "$BASE_IMG" "$WORK/agentctx" \
  && podman build -q -t "$AGENT_IMG" --build-arg BASE="$BASE_IMG" -f "$AP/agent.Containerfile" "$AP"; } >"$WORK/build.log" 2>&1 \
  && PASS "images built" || { cat "$WORK/build.log"; DIE "podman build"; }

STEP "start hub (TLS self-issued, persistent volume $VOL)"
podman network create "$NET" >/dev/null || DIE "network create"
podman volume create "$VOL" >/dev/null || DIE "volume create"
cat >"$WORK/hub.env" <<EOF2
APP_BOOTSTRAP_TOKEN=$API_TOKEN
AUTH_MODE=bootstrap
APP_CERTIFICATE_PROVIDER=ca
APP_DISCOVERY_PROVIDER=db
APP_NOTIFICATION_PROVIDER=file
KRYPTKEEPER_TLS_SELF_ISSUE=true
KRYPTKEEPER_TLS_SANS=$HUB,localhost,127.0.0.1
APP_CREDENTIAL_STORE_PASSPHRASE=uat-lr-cred-passphrase-32-bytes-long!
KRYPTKEEPER_KEYSTORE_PASSPHRASE=uat-lr-keystore-passphrase-32-bytes!
KRYPTKEEPER_DATA_DIR=/data
KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true
KRYPTKEEPER_CA_NAME=UAT Listener Rotation CA
APP_BIND_ADDR=0.0.0.0
PORT=$HUB_PORT
KRYPTKEEPER_AGENT_ENROLLMENT_SECRETS=$ENROLL_SECRET
KRYPTKEEPER_BASE_URL=https://$HUB:$HUB_PORT
HEALTHCHECK_URL=https://127.0.0.1:$HUB_PORT/healthz
HEALTHCHECK_CA_FILE=/data/tls/ca.pem
EOF2
podman run -d --name "$HUB" --network "$NET" -v "$VOL:/data" -p "127.0.0.1:${HUB_PORT}:${HUB_PORT}" \
  --env-file "$WORK/hub.env" "$HUB_IMG" >/dev/null || DIE "start hub"
for _ in $(seq 1 40); do fetch_ca "$CA" && break; sleep 1; done
[ -s "$CA" ] || { podman logs "$HUB" 2>&1 | tail -20; DIE "hub never wrote /data/tls/ca.pem"; }
wait_ready 40 || { podman logs "$HUB" 2>&1 | tail -20; DIE "hub /readyz never verified against its own CA"; }
CA_FP0="$(ca_fp "$CA")"
PASS "hub ready; CA fingerprint $CA_FP0"

STEP "start agent (self-enrols once) and nginx proxy"
podman run -d --name "$AGENT" --network "$NET" --network-alias agenthost \
  -v "$CA:/etc/kryptkeeper/hub-ca.pem:ro" \
  -e KRYPTKEEPER_HUB_URL="https://$HUB:$HUB_PORT" \
  -e KRYPTKEEPER_HUB_CA_CERT_FILE=/etc/kryptkeeper/hub-ca.pem \
  -e KRYPTKEEPER_AGENT_ENROLLMENT_SECRET="$ENROLL_SECRET" \
  -e KRYPTKEEPER_AGENT_NAME=kk-uat-lr-agent \
  -e KRYPTKEEPER_AGENT_CREDENTIALS_FILE=/var/lib/kk-agent-credentials.env \
  -e KRYPTKEEPER_POLL_INTERVAL="$POLL" \
  -e KRYPTKEEPER_SCAN_PATHS=/etc/nginx/ssl -e KRYPTKEEPER_CONFIG_PATHS=/etc/nginx \
  "$AGENT_IMG" >/dev/null || DIE "start agent"
GW="$(podman network inspect "$NET" --format '{{(index .Subnets 0).Gateway}}')"
cat >"$SHARE/proxy.conf" <<EOF2
server {
  listen 80;
  resolver $GW valid=1s;
  location / {
    set \$up https://$HUB:$HUB_PORT;
    proxy_pass \$up;
    proxy_ssl_verify on;
    proxy_ssl_trusted_certificate /etc/nginx/hub-ca.pem;
    proxy_ssl_verify_depth 3;
    proxy_ssl_server_name on;
    proxy_ssl_name $HUB;
  }
}
EOF2
podman run -d --name "$PROXY" --network "$NET" -p "127.0.0.1:${PROXY_PORT}:80" \
  -v "$SHARE/proxy.conf:/etc/nginx/conf.d/default.conf:ro" -v "$CA:/etc/nginx/hub-ca.pem:ro" \
  docker.io/library/nginx:alpine >/dev/null || DIE "start proxy"

polled=""
for _ in $(seq 1 40); do
  podman logs "$AGENT" 2>&1 | grep -q "hub accepted" && { polled=1; break; }
  sleep 1
done
[ -n "$polled" ] && PASS "agent enrolled and completed a successful poll" || { podman logs "$AGENT" 2>&1 | tail -20; DIE "agent never completed a poll"; }
sleep $((POLL + 2))   # at least one more steady-state poll before the baseline
E0="$(register_count)"
ENROL_LOG0="$(podman logs "$AGENT" 2>&1 | grep -c 'registering agent')"
S0="$(leaf_serial)"
code0="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${PROXY_PORT}/healthz")"
echo "E0 (agent.register audit events)=$E0 agent-log 'registering agent' lines=$ENROL_LOG0 S0=$S0 proxy_http=$code0"
[ -n "$S0" ] && [ -n "$E0" ] && [ "$code0" = 200 ] || DIE "baseline incomplete (S0='$S0' E0='$E0' proxy=$code0)"

STEP "force renewal: stop hub, remove tls.crt+tls.key from the volume, start hub"
LINES_BEFORE="$(podman logs "$AGENT" 2>&1 | wc -l | tr -d ' ')"
T_STOP="$(now)"
podman stop -t 5 "$HUB" >/dev/null || DIE "stop hub"
podman run --rm -v "$VOL:/data" --entrypoint rm "$HUB_IMG" -f /data/tls/tls.crt /data/tls/tls.key || DIE "remove listener leaf"
podman start "$HUB" >/dev/null || DIE "start hub"
for _ in $(seq 1 60); do wait_ready 1 && break; done
wait_ready 5 || { podman logs "$HUB" 2>&1 | tail -20; DIE "hub /readyz never came back"; }
T_READY="$(now)"
LINES_AT_READY="$(podman logs "$AGENT" 2>&1 | wc -l | tr -d ' ')"
podman logs "$HUB" 2>&1 | grep "\[TLS\]" | tail -2
echo "hub down->ready: $(python3 -c "print(round($T_READY-$T_STOP,1))")s"

STEP "serial_changes"
S1="$(leaf_serial)"
echo "S0=$S0 S1=$S1"
if [ -n "$S1" ] && [ "$S1" != "$S0" ]; then PASS "serial_changes: listener leaf re-issued"; else FAIL "serial_changes: S1 '$S1' vs S0 '$S0'"; fi

STEP "new_leaf_verifies_against_old_ca"
NEWCA="$WORK/ca-after.pem"
fetch_ca "$NEWCA" || FAIL "could not read ca.pem after renewal"
if [ -s "$NEWCA" ] && [ "$(ca_fp "$NEWCA")" = "$CA_FP0" ]; then PASS "CA fingerprint unchanged ($CA_FP0)"; else FAIL "CA changed across renewal"; fi
if verify_ok; then PASS "new_leaf_verifies_against_old_ca: verify return code 0 against the pre-renewal hub-ca.pem"; else FAIL "new leaf does not verify against the old CA"; fi

STEP "agent_reconnects_without_reenroll (deadline 2 x ${POLL}s from hub-ready)"
deadline=$(python3 -c "print($T_READY + 2*$POLL)")
got=""; T_POLL=""
while [ "$(python3 -c "print(1 if $(now) < $deadline else 0)")" = 1 ]; do
  if podman logs "$AGENT" 2>&1 | tail -n +$((LINES_AT_READY + 1)) | grep -q "hub accepted"; then T_POLL="$(now)"; got=1; break; fi
  sleep 1
done
NEWLOG="$(podman logs "$AGENT" 2>&1 | tail -n +$((LINES_BEFORE + 1)))"
E1="$(register_count)"
ENROL_LOG1="$(podman logs "$AGENT" 2>&1 | grep -c 'registering agent')"
echo "E1=$E1 (E0=$E0) agent-log 'registering agent' lines=$ENROL_LOG1 (was $ENROL_LOG0)"
echo "agent log since stop:"; printf '%s\n' "$NEWLOG" | sed 's/^/  | /'
[ -n "$got" ] && echo "first successful poll $(python3 -c "print(round($T_POLL-$T_READY,1))")s after hub-ready"
if [ -n "$got" ] && [ "$E1" = "$E0" ] && [ "$ENROL_LOG1" = "$ENROL_LOG0" ]; then
  PASS "agent_reconnects_without_reenroll: poll accepted within 2 intervals, 0 re-enrolments"
else
  FAIL "agent_reconnects_without_reenroll (polled='$got' E0=$E0 E1=$E1)"
fi
echo "agent container started at $(podman inspect "$AGENT" --format '{{.State.StartedAt}}') (never stopped by the harness)"

STEP "healthcheck_verifies"
if podman exec "$HUB" /usr/local/bin/healthcheck; then PASS "healthcheck_verifies: /healthcheck exit 0 with HEALTHCHECK_CA_FILE (verified TLS)"; else FAIL "healthcheck exit non-zero"; fi

STEP "nginx_proxy_verifies"
code1="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${PROXY_PORT}/healthz")"
if [ "$code1" = 200 ]; then PASS "nginx_proxy_verifies: GET through proxy (proxy_ssl_verify on) = 200 after renewal"; else FAIL "proxy returned $code1"; podman logs "$PROXY" 2>&1 | tail -5; fi

STEP "no_skip_verify_flags"
pat="-k( |\$)|--insec""ure|InsecureSkip""Verify|proxy_ssl_verify +o""ff"
if grep -nE -- "$pat" "$HERE/listener-rotation.sh" | grep -v 'pat='; then FAIL "no_skip_verify_flags: found a verification bypass"; else PASS "no_skip_verify_flags: none in this harness"; fi
grep -q 'proxy_ssl_verify on;' "$SHARE/proxy.conf" && PASS "proxy config has proxy_ssl_verify on"

echo
if [ "$FAILED" -ne 0 ]; then echo "RESULT: FAIL"; exit 1; fi
echo "RESULT: PASS"
