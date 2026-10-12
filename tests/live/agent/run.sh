#!/usr/bin/env bash
# W19-04 live UAT: kryptkeeper-agent against a real hub, in podman containers.
# Idempotent, non-zero exit on failure, always cleans up. No docker.
#
# The hub and the agent host share a podman network (hub "kkhub", agent host
# "agenthost"). The hub's ACME server refuses localhost names (RFC 6761) and
# http-01 fetches over loopback, so the agent's certificate is for the real
# name "agenthost" and the hub reaches its port 80 across the network, exactly
# as it would reach a server in production. See tests/live/autopilot/run.sh,
# which reuses the same hub/agent fixtures.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
HERE="$ROOT/tests/live/agent"
AP="$ROOT/tests/live/autopilot"
WORKDIR="$(mktemp -d /tmp/kk-uat-agent.XXXXXX)"
# podman machine on macOS only virtiofs-mounts $HOME (/Users), not /tmp, so the
# hub CA export bind-mounted into the agent container lives under $HOME.
CA_EXPORT_DIR="$(mktemp -d "$HOME/.kk-uat-agent-ca.XXXXXX")"

# Free host ports and a per-run id, so concurrent runs (another worktree, a CI
# job) never share container names, the network or published ports.
RUN_ID="$(openssl rand -hex 3)"
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
NET="kk-uat-agent-net-$RUN_ID"
HUB_IMAGE="localhost/kk-uat-agent-hub:$RUN_ID"
BASE_IMAGE="localhost/kk-uat-agent-fixture-base:$RUN_ID"
IMAGE="localhost/kk-uat-agent-fixture:$RUN_ID"
HUB="kkhub-$RUN_ID"
CONTAINER="agenthost-$RUN_ID"
HUB_PORT="$(free_port)"
AGENT_TLS_PORT="$(free_port)"
PASS_COUNT=0
FAIL_COUNT=0

log()  { printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*"; }
pass() { PASS_COUNT=$((PASS_COUNT+1)); log "PASS: $*"; }
fail() { FAIL_COUNT=$((FAIL_COUNT+1)); log "FAIL: $*"; }

cleanup() {
  log "cleaning up"
  podman rm -f "$CONTAINER" "$HUB" >/dev/null 2>&1 || true
  podman network rm "$NET" >/dev/null 2>&1 || true
  podman rmi -f "$HUB_IMAGE" "$BASE_IMAGE" "$IMAGE" >/dev/null 2>&1 || true
  rm -f "$HERE/kryptkeeper-agent"
  rm -rf "$WORKDIR" "$CA_EXPORT_DIR"
}
trap cleanup EXIT

podman rm -f "$CONTAINER" "$HUB" >/dev/null 2>&1 || true
podman network rm "$NET" >/dev/null 2>&1 || true

case "$(podman info --format '{{.Host.Arch}}' 2>/dev/null || echo amd64)" in
  arm64|aarch64) GOARCH=arm64 ;;
  *) GOARCH=amd64 ;;
esac
log "podman machine GOARCH=$GOARCH"

# --- build agent + hub binaries for the container arch ---
mkdir -p "$WORKDIR/hubctx"
if ! (cd "$ROOT" && GOOS=linux GOARCH="$GOARCH" CGO_ENABLED=0 go build -o "$WORKDIR/kryptkeeper-agent" ./cmd/kryptkeeper-agent); then
  fail "build kryptkeeper-agent"; exit 1
fi
if ! (cd "$ROOT" && GOOS=linux GOARCH="$GOARCH" CGO_ENABLED=0 go build -o "$WORKDIR/hubctx/kryptkeeper" ./cmd/kryptkeeper); then
  fail "build kryptkeeper hub"; exit 1
fi
pass "build kryptkeeper-agent and hub (commit $(cd "$ROOT" && git rev-parse --short HEAD), GOARCH=$GOARCH)"

# --- images ---
cp "$AP/hub.Containerfile" "$WORKDIR/hubctx/Containerfile"
cp "$WORKDIR/kryptkeeper-agent" "$HERE/kryptkeeper-agent"
if ! { podman build -t "$HUB_IMAGE" "$WORKDIR/hubctx" \
    && podman build -t "$BASE_IMAGE" "$HERE" \
    && podman build -t "$IMAGE" --build-arg BASE="$BASE_IMAGE" -f "$AP/agent.Containerfile" "$AP"; } >"$WORKDIR/build.log" 2>&1; then
  fail "podman build (see $WORKDIR/build.log)"; cat "$WORKDIR/build.log"; exit 1
fi
rm -f "$HERE/kryptkeeper-agent"
pass "podman build hub and fixture images"

# --- hub in a container on the shared network ---
podman network create "$NET" >/dev/null || { fail "network create"; exit 1; }
cat >"$WORKDIR/hub.env" <<EOF
APP_BOOTSTRAP_TOKEN=uat-token
AUTH_MODE=bootstrap
APP_CERTIFICATE_PROVIDER=ca
APP_DISCOVERY_PROVIDER=db
APP_NOTIFICATION_PROVIDER=file
KRYPTKEEPER_TLS_SANS=$HUB,localhost,127.0.0.1
APP_CREDENTIAL_STORE_PASSPHRASE=uat-cred-passphrase-32-bytes-long!!
KRYPTKEEPER_KEYSTORE_PASSPHRASE=uat-keystore-passphrase-32-bytes!!
KRYPTKEEPER_DATA_DIR=/data
APP_CA_FILE=/data/cas.json
APP_TEMPLATE_FILE=/data/templates.json
APP_CERTIFICATE_FILE=/data/certificates.json
APP_AUDIT_FILE=/data/audit.json
APP_CERTS_SUMMARY_FILE=/data/certs_summary.json
KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true
KRYPTKEEPER_CA_NAME=UAT Root CA
APP_BIND_ADDR=0.0.0.0
PORT=$HUB_PORT
KRYPTKEEPER_AGENT_ENROLLMENT_SECRETS=uat-enrollment-secret
KRYPTKEEPER_BASE_URL=https://$HUB:$HUB_PORT
EOF
log "starting hub on :$HUB_PORT"
podman run -d --name "$HUB" --network "$NET" -p "127.0.0.1:$HUB_PORT:$HUB_PORT" --env-file "$WORKDIR/hub.env" "$HUB_IMAGE" >/dev/null \
  || { fail "start hub container"; exit 1; }

BASE="https://127.0.0.1:$HUB_PORT"
for _ in $(seq 1 30); do curl -fsSk "$BASE/healthz" >/dev/null 2>&1 && break; sleep 1; done
if ! curl -fsSk "$BASE/healthz" >/dev/null 2>&1; then
  fail "hub healthz never became ready"; podman logs "$HUB" 2>&1 | tail -30; exit 1
fi
pass "hub booted and answers /healthz over TLS"

# --- export the hub's self-issued CA (unauthenticated EST cacerts, PKCS#7) ---
HUB_CA_PEM="$CA_EXPORT_DIR/hub-ca.pem"
if curl -sSk --max-time 3 -o "$WORKDIR/cacerts.b64" "$BASE/.well-known/est/cacerts" \
    && openssl base64 -d -A -in "$WORKDIR/cacerts.b64" -out "$WORKDIR/cacerts.p7" \
    && openssl pkcs7 -inform der -in "$WORKDIR/cacerts.p7" -print_certs -out "$HUB_CA_PEM" \
    && [ -s "$HUB_CA_PEM" ]; then
  pass "exported the hub's self-issued CA via EST cacerts"
else
  fail "could not export the hub's CA via EST cacerts"; exit 1
fi

if podman run --rm --network "$NET" -v "$HUB_CA_PEM:/ca.pem:ro" docker.io/curlimages/curl -s --cacert /ca.pem \
    "https://$HUB:$HUB_PORT/healthz" | grep -q '.'; then
  pass "containers on the network reach the hub as $HUB:$HUB_PORT (real chain verification, no -k)"
else
  fail "containers cannot reach $HUB:$HUB_PORT"; exit 1
fi

DIRECTORY_JSON="$(podman run --rm --network "$NET" -v "$HUB_CA_PEM:/ca.pem:ro" docker.io/curlimages/curl -s --cacert /ca.pem \
  "https://$HUB:$HUB_PORT/acme/directory")"
if printf '%s' "$DIRECTORY_JSON" | grep -q "$HUB:$HUB_PORT"; then
  pass "ACME directory URLs use $HUB:$HUB_PORT (KRYPTKEEPER_BASE_URL honored): $DIRECTORY_JSON"
else
  fail "ACME directory does not advertise a network-reachable base URL: $DIRECTORY_JSON"
fi

# --- Step 1: enrol ---
REG_RESP="$(curl -fsSk -X POST "$BASE/api/v1/agent/register" \
  -H 'Content-Type: application/json' \
  -d '{"name":"kk-uat-agent","type":"linux","enrollment_secret":"uat-enrollment-secret"}')"
AGENT_ID="$(printf '%s' "$REG_RESP" | grep -o '"agent_id":"[^"]*"' | cut -d'"' -f4)"
AGENT_TOKEN="$(printf '%s' "$REG_RESP" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)"
if [ -z "$AGENT_ID" ] || [ -z "$AGENT_TOKEN" ]; then
  fail "agent registration did not return agent_id/token: $REG_RESP"; exit 1
fi
pass "agent registered via POST /api/v1/agent/register (agent_id=$AGENT_ID)"

# --- run the agent container ---
log "starting agent container"
if ! podman run -d --name "$CONTAINER" --network "$NET" --network-alias agenthost \
    -p "127.0.0.1:$AGENT_TLS_PORT:443" \
    -v "$HUB_CA_PEM:/etc/kryptkeeper/hub-ca.pem:ro" \
    -e KRYPTKEEPER_HUB_URL="https://$HUB:$HUB_PORT" \
    -e KRYPTKEEPER_HUB_CA_CERT_FILE="/etc/kryptkeeper/hub-ca.pem" \
    -e KRYPTKEEPER_AGENT_ID="$AGENT_ID" \
    -e KRYPTKEEPER_AGENT_TOKEN="$AGENT_TOKEN" \
    -e KRYPTKEEPER_AGENT_NAME="kk-uat-agent" \
    -e KRYPTKEEPER_POLL_INTERVAL=8 \
    -e KRYPTKEEPER_SCAN_PATHS="/etc/nginx/ssl,/etc/ssl/certs-extra" \
    -e KRYPTKEEPER_CONFIG_PATHS="/etc/nginx" \
    -e KRYPTKEEPER_WEB_ROOT="/var/www/html" \
    "$IMAGE" >"$WORKDIR/run.log" 2>&1; then
  fail "podman run agent container"; cat "$WORKDIR/run.log"; exit 1
fi
pass "podman run agent container"

BASELINE_FP=""
for _ in $(seq 1 15); do
  BASELINE_FP="$(openssl s_client -connect 127.0.0.1:$AGENT_TLS_PORT -servername agenthost </dev/null 2>/dev/null \
    | openssl x509 -noout -fingerprint -sha256 2>/dev/null)"
  [ -n "$BASELINE_FP" ] && break
  sleep 1
done
if [ -n "$BASELINE_FP" ]; then pass "captured baseline leaf fingerprint on :8445 ($BASELINE_FP)"
else fail "could not fetch the fixture's baseline leaf on :8445"; fi

# --- agent shows active ---
ACTIVE=""
for _ in $(seq 1 15); do
  RESP="$(curl -fsSk -H "Authorization: Bearer uat-token" "$BASE/api/v1/agents")"
  if printf '%s' "$RESP" | python3 -c "
import json,sys
try:
  d=json.load(sys.stdin)
  for a in d.get('agents',[]):
    if a.get('id')=='$AGENT_ID' and a.get('status')=='active':
      sys.exit(0)
except Exception:
  pass
sys.exit(1)
" 2>/dev/null; then ACTIVE="1"; break; fi
  sleep 2
done
if [ -n "$ACTIVE" ]; then pass "GET /api/v1/agents shows agent $AGENT_ID as active (paired + heartbeating)"
else fail "agent never showed active in GET /api/v1/agents: $RESP"; fi

# --- Step 2: inventory arrived ---
INV_OK=""
for _ in $(seq 1 15); do
  RESP="$(curl -fsSk -H "Authorization: Bearer uat-token" "$BASE/api/v1/agents")"
  COUNT="$(printf '%s' "$RESP" | python3 -c "
import json,sys
d=json.load(sys.stdin)
for a in d.get('agents',[]):
    if a.get('id')=='$AGENT_ID':
        print(a.get('inventory_count',0)); break
" 2>/dev/null)"
  if [ -n "$COUNT" ] && [ "$COUNT" -ge 4 ] 2>/dev/null; then INV_OK="1"; break; fi
  sleep 2
done
if [ -n "$INV_OK" ]; then pass "hub recorded inventory_count=$COUNT (expected >=4: 1 nginx leaf + 3 extras)"
else fail "hub never recorded expected inventory (last count: ${COUNT:-unknown})"; podman logs "$CONTAINER" 2>&1 | tail -40; fi

# --- documented-inert step: a managed target with install_mode=agent ---
TGT_RESP="$(curl -fsSk -X POST "$BASE/api/v1/targets" \
  -H "Authorization: Bearer uat-token" -H 'Content-Type: application/json' \
  -d '{"name":"kk-uat-agent-target","host":"agenthost","discovery_mode":"agent","install_mode":"agent","renewal_method":"manual"}' 2>&1)"
if printf '%s' "$TGT_RESP" | grep -q '"install_mode":"agent"'; then
  pass "managed target with install_mode=agent created (documented inert per managed_target_store.go -- not the task-queue trigger)"
else
  log "managed target create response (non-fatal): $TGT_RESP"
fi

# --- Step 3: agent-mode renewal task + execution ---
# The agent polls tasks itself, so the queued task can be consumed before this
# script looks; the durable evidence is the install outcome and audit below.
TASK_JSON=""
for _ in $(seq 1 10); do
  TASK_JSON="$(curl -fsSk -H "X-Agent-ID: $AGENT_ID" -H "X-Agent-Token: $AGENT_TOKEN" "$BASE/api/v1/agent/tasks")"
  printf '%s' "$TASK_JSON" | grep -q '"task_id"' && break
  sleep 1
done
if printf '%s' "$TASK_JSON" | grep -q '"task_id"'; then
  pass "hub queued a renewal task via matchRenewalTasks: $TASK_JSON"
else
  log "no queued task visible (the agent may already have consumed it); checking the agent log"
fi

log "waiting up to 120s for the agent to install the renewed cert"
AGENT_LOG=""
for _ in $(seq 1 24); do
  sleep 5
  AGENT_LOG="$(podman logs "$CONTAINER" 2>&1)"
  printf '%s' "$AGENT_LOG" | grep -q "installed.*outcome=" && break
done
if printf '%s' "$AGENT_LOG" | grep -q "task .*: renew"; then pass "agent received a renewal task from the hub"
else fail "agent log shows no received renewal task"; fi
if printf '%s' "$AGENT_LOG" | grep -q "installed.*outcome="; then
  pass "agent installed a renewed cert and reported outcome to the hub"
else
  fail "agent never reported an installed/outcome log line; last log lines:"
  printf '%s\n' "$AGENT_LOG" | tail -30
fi

# --- Step 4: hub-side audit of the result ---
AUDIT_JSON="$(curl -fsSk -H "Authorization: Bearer uat-token" "$BASE/api/v1/audit?action=agent.renewal_result" 2>&1)"
if printf '%s' "$AUDIT_JSON" | grep -q '"action":"agent.renewal_result"'; then
  pass "hub audit log recorded agent.renewal_result"
else
  fail "hub audit log has no agent.renewal_result entry: $AUDIT_JSON"
fi

# --- Step 5: openssl proves the leaf changed, chains to the hub CA, for the name ---
RENEWED_FP=""
for _ in $(seq 1 10); do
  RENEWED_FP="$(openssl s_client -connect 127.0.0.1:$AGENT_TLS_PORT -servername agenthost </dev/null 2>/dev/null \
    | openssl x509 -noout -fingerprint -sha256 2>/dev/null)"
  [ -n "$RENEWED_FP" ] && [ "$RENEWED_FP" != "$BASELINE_FP" ] && break
  sleep 3
done
if [ -n "$RENEWED_FP" ] && [ -n "$BASELINE_FP" ] && [ "$RENEWED_FP" != "$BASELINE_FP" ]; then
  pass "leaf on :8445 changed after renewal (baseline $BASELINE_FP -> renewed $RENEWED_FP)"
else
  fail "leaf on :8445 did not change after renewal (still $RENEWED_FP)"
fi
VOUT="$(openssl s_client -connect 127.0.0.1:$AGENT_TLS_PORT -servername agenthost -CAfile "$HUB_CA_PEM" -verify_return_error -verify_hostname agenthost </dev/null 2>&1)"
if printf '%s' "$VOUT" | grep -q "Verify return code: 0 (ok)"; then
  pass "renewed leaf verifies against the hub CA for agenthost (UAT Root CA)"
else
  fail "renewed leaf does not verify against the hub CA: $(printf '%s' "$VOUT" | grep -i verif)"
fi

echo
echo "=== W19-04 summary: $PASS_COUNT passed, $FAIL_COUNT failed ==="
exit $((FAIL_COUNT > 0))
