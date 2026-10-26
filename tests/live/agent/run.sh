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
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib/podman.sh"
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
# http_code: print only the status (no -f, so 4xx is captured); body in $WORKDIR/last.body.
http_code() { curl -sSk -o "$WORKDIR/last.body" -w '%{http_code}' "$@"; }

cleanup() {
  log "cleaning up"
  kk_rm "$CONTAINER" "$HUB"
  podman network rm "$NET" >/dev/null 2>&1 || true
  podman rmi -f "$HUB_IMAGE" "$BASE_IMAGE" "$IMAGE" >/dev/null 2>&1 || true
  rm -f "$HERE/kryptkeeper-agent"
  rm -rf "$WORKDIR" "$CA_EXPORT_DIR"
}
trap cleanup EXIT

kk_rm "$CONTAINER" "$HUB"
podman network rm "$NET" >/dev/null 2>&1 || true

GOARCH="$(kk_goarch)"
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
# The W24-16 keystore fixtures are generated, never committed (.gitignore
# covers *.jks, *.p12 and kubeconfig*), so a fresh checkout has none of them.
if [ ! -s "$HERE/fixtures/store3.jks" ] || [ ! -s "$HERE/fixtures/store2.p12" ] || [ ! -s "$HERE/fixtures/kubeconfig" ]; then
  if ! podman run --rm -v "$HERE/fixtures:/out" docker.io/library/ubuntu:24.04 sh -c \
      'apt-get update -qq && apt-get install -y -qq openssl openjdk-17-jre-headless >/dev/null && cd /out && sh gen-keystores.sh' \
      >"$WORKDIR/keystores.log" 2>&1; then
    fail "generate keystore fixtures (see $WORKDIR/keystores.log)"; cat "$WORKDIR/keystores.log"; exit 1
  fi
  pass "generated keystore fixtures (store3.jks, store2.p12, kubeconfig)"
fi

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
    -e KRYPTKEEPER_SCAN_PATHS="/etc/nginx/ssl,/etc/ssl/certs-extra,/opt/keystores" \
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

# --- W24-16: keystores, kubeconfig, hub-DB hygiene, out-of-band replacement ---
# W24-45: these checks read GET /api/v1/agents/{id}/inventory. The hub DB is
# still copied below, only for the PRIVATE KEY hygiene scan of the agent_* tables.
inv_json() { curl -fsSk -H "Authorization: Bearer uat-token" "$BASE/api/v1/agents/$AGENT_ID/inventory?limit=500" 2>/dev/null; }
hub_db() {
  rm -rf "$WORKDIR/hubdb"; mkdir -p "$WORKDIR/hubdb"
  podman cp "$HUB:/data/." "$WORKDIR/hubdb/" >/dev/null 2>&1
  echo "$WORKDIR/hubdb/kryptkeeper.db"
}
inv_sources() { inv_json | python3 -c "
import json,sys
for c in json.load(sys.stdin).get('certificates',[]): print(c.get('source',''))" 2>/dev/null; }
# Fingerprint of the certificate whose source ends in the given path suffix.
inv_fp_for() { inv_json | python3 -c "
import json,sys
for c in json.load(sys.stdin).get('certificates',[]):
    if c.get('source','').endswith('$1'): print(c.get('fingerprint','')); break" 2>/dev/null; }
count_src() { grep -c -E "$1" <<<"$2" || true; }

# Wait (one agent poll is 8 s) until all 6 keystore-sourced rows are present.
SRCS=""
for _ in $(seq 1 15); do
  SRCS="$(inv_sources)"
  [ "$(count_src '^(jks|pkcs12|kubeconfig):' "$SRCS")" -ge 6 ] && break
  sleep 2
done
N_JKS="$(count_src '^jks:/opt/keystores/store3.jks$' "$SRCS")"
N_P12="$(count_src '^pkcs12:/opt/keystores/store2.p12$' "$SRCS")"
N_KUBE="$(count_src '^kubeconfig:/opt/keystores/kubeconfig$' "$SRCS")"
N_ALL="$(count_src '^(jks|pkcs12|kubeconfig):' "$SRCS")"
[ "$N_JKS" = 3 ] && pass "JKS: exactly 3 certs from /opt/keystores/store3.jks" \
  || { fail "JKS: expected 3 certs from store3.jks, got $N_JKS (sources: $(sort -u <<<"$SRCS" | tr '\n' ' '))"; }
[ "$N_P12" = 2 ] && pass "PKCS#12: exactly 2 certs from /opt/keystores/store2.p12" \
  || fail "PKCS#12: expected 2 certs from store2.p12, got $N_P12"
[ "$N_KUBE" = 1 ] && pass "kubeconfig: exactly 1 cert from /opt/keystores/kubeconfig" \
  || fail "kubeconfig: expected 1 cert, got $N_KUBE"
[ "$N_ALL" = 6 ] && pass "no extra keystore-sourced certs (6 total)" \
  || fail "keystore-sourced inventory rows: expected 6, got $N_ALL"

# Out-of-band replacement of a served cert. extra1.pem (not the nginx leaf) is
# replaced so the autopilot renewal and its agent.renewal_result suppression
# cannot explain the change. Same CN, new key.
OLD_FP="$(inv_fp_for /etc/ssl/certs-extra/extra1.pem)"
T_REPLACE=$(date +%s)
podman exec "$CONTAINER" sh -c 'openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -keyout /tmp/extra1-new.key -out /etc/ssl/certs-extra/extra1.pem -days 301 -nodes -subj "/CN=extra1.kryptkeeper.uat.local" >/dev/null 2>&1; rm -f /tmp/extra1-new.key'
ALERT=""
for _ in $(seq 1 13); do   # 2 * poll interval (8 s) + 10 s margin
  ALERT="$(curl -fsSk -H "Authorization: Bearer uat-token" "$BASE/api/v1/audit?action=discovery.scan_diff.certificate_replaced&limit=100" 2>/dev/null \
    | python3 -c "
import json,sys
rows=json.load(sys.stdin).get('data',[])
print('\n'.join(r.get('change_summary','') for r in rows))" 2>/dev/null)"
  grep -q 'extra1.pem' <<<"$ALERT" && break
  sleep 2
done
ELAPSED=$(( $(date +%s) - T_REPLACE ))
NEW_FP="$(inv_fp_for /etc/ssl/certs-extra/extra1.pem)"
if grep -q 'extra1.pem' <<<"$ALERT"; then
  pass "CERTIFICATE_REPLACED raised for extra1.pem within ${ELAPSED}s of the out-of-band replacement (audit discovery.scan_diff.certificate_replaced)"
else
  fail "no CERTIFICATE_REPLACED alert for extra1.pem within ${ELAPSED}s (old=$OLD_FP new=$NEW_FP)"
fi
if [ -n "$OLD_FP" ] && [ -n "$NEW_FP" ] && [ "$OLD_FP" != "$NEW_FP" ]; then
  pass "inventory now carries the replacement leaf for extra1.pem ($OLD_FP -> $NEW_FP)"
else
  fail "inventory fingerprint for extra1.pem did not change (old=$OLD_FP new=$NEW_FP)"
fi
if grep -q '/opt/keystores' <<<"$ALERT"; then fail "alert raised for an unchanged keystore source"
else pass "0 alerts for the unchanged keystore sources"; fi

# The API view must carry no key material either.
if inv_json | grep -q 'PRIVATE KEY'; then fail "GET /agents/{id}/inventory carries a PRIVATE KEY header"
else pass "GET /agents/{id}/inventory carries 0 PEM private-key headers"; fi

# Hub DB hygiene: no PEM private-key header in the agent_* tables.
DB="$(hub_db)"
PK_HITS="$(sqlite3 "$DB" ".dump agent_inventory agent_endpoints agent_tasks agent_results agents" 2>/dev/null | grep -c 'PRIVATE KEY' || true)"
if [ -f "$DB" ] && [ "${PK_HITS:-1}" = 0 ]; then
  pass "hub DB agent_* tables contain 0 PEM private-key headers"
else
  fail "hub DB agent_* tables: PRIVATE KEY hits=${PK_HITS:-unreadable} (db=$DB)"
fi

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

# --- W29-07: enrollment hardening (W29-06 per-agent single-use tokens) ---
# Runs after the renewal assertions: extra agents registered earlier would
# disturb the agents-list / inventory_count checks. Test-only values (uat-*);
# the minted token is never printed, only its id.
REG_URL="$BASE/api/v1/agent/register"
JSON_H='Content-Type: application/json'

C="$(http_code -X POST "$REG_URL" -H "$JSON_H" -d '{"name":"anon","type":"linux"}')"
if { [ "$C" = 401 ] || [ "$C" = 403 ]; } && ! grep -q 'KRYPTKEEPER_' "$WORKDIR/last.body"; then
  pass "W29-07 anonymous registration refused ($C), no gate internals in the body"
else fail "W29-07 anonymous registration: status $C body $(cat "$WORKDIR/last.body")"; fi

C="$(http_code -X POST "$REG_URL" -H "$JSON_H" -d '{"name":"anon","type":"linux","enrollment_secret":"definitely-wrong"}')"
if [ "$C" = 401 ] || [ "$C" = 403 ]; then pass "W29-07 wrong enrollment secret refused ($C)"
else fail "W29-07 wrong secret: status $C"; fi

HUB_LOG="$(podman logs "$HUB" 2>&1)"
if printf '%s' "$HUB_LOG" | grep -q 'shared, reusable secret' \
   && ! printf '%s' "$HUB_LOG" | grep -q 'uat-enrollment-secret' \
   && ! printf '%s' "$HUB_LOG" | grep -q 'registration is OPEN'; then
  pass "W29-07 hub logged the shared-secret warning, open mode is off, secret never logged"
else fail "W29-07 hub log: missing shared-secret warning, open-mode line present, or secret leaked"; fi

mint_token() { # prints "<id> <token>" or nothing
  local r id tok
  r="$(curl -fsSk -X POST "$BASE/api/v1/agent/enrollment-tokens" -H "Authorization: Bearer uat-token" -H "$JSON_H" -d "{\"label\":\"$1\",\"ttl_seconds\":3600}")" || return 1
  id="$(printf '%s' "$r" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)"
  tok="$(printf '%s' "$r" | grep -o '"token":"[^"]*"' | head -1 | cut -d'"' -f4)"
  [ -n "$id" ] && [ -n "$tok" ] && printf '%s %s' "$id" "$tok"
}
ENR_PAIR="$(mint_token w29-07)"
ENR_ID="${ENR_PAIR% *}"; ENR_TOK="${ENR_PAIR#* }"
if [ -n "$ENR_PAIR" ]; then pass "W29-07 admin minted a single-use enrollment token (id=$ENR_ID)"
else fail "W29-07 token mint returned no id/token"; fi

NEW_ID=""; NEW_TOKEN=""
if [ -n "$ENR_PAIR" ]; then
  C="$(http_code -X POST "$REG_URL" -H "$JSON_H" -d "{\"name\":\"kk-uat-agent-tok\",\"type\":\"linux\",\"enrollment_token\":\"$ENR_TOK\"}")"
  NEW_ID="$(grep -o '"agent_id":"[^"]*"' "$WORKDIR/last.body" | cut -d'"' -f4)"
  NEW_TOKEN="$(grep -o '"token":"[^"]*"' "$WORKDIR/last.body" | cut -d'"' -f4)"
  if [ "$C" = 201 ] && [ -n "$NEW_ID" ] && [ -n "$NEW_TOKEN" ]; then pass "W29-07 token redeemed once: 201 with per-agent credentials (agent_id=$NEW_ID)"
  else fail "W29-07 token redeem: status $C"; fi

  C="$(http_code -X POST "$REG_URL" -H "$JSON_H" -d "{\"name\":\"kk-uat-agent-tok2\",\"type\":\"linux\",\"enrollment_token\":\"$ENR_TOK\"}")"
  if [ "$C" = 401 ] || [ "$C" = 403 ]; then pass "W29-07 second redemption of the same token refused ($C)"
  else fail "W29-07 second redeem: status $C"; fi
else
  fail "W29-07 redeem skipped (no token)"; fail "W29-07 second-redeem skipped (no token)"
fi

if [ -n "$NEW_ID" ]; then
  CT="$(http_code "$BASE/api/v1/agent/tasks" -H "X-Agent-ID: $NEW_ID" -H "X-Agent-Token: $NEW_TOKEN")"; TASKS_OK=0
  grep -q '"tasks"' "$WORKDIR/last.body" && TASKS_OK=1
  CH="$(http_code -X POST "$BASE/api/v1/agent/heartbeat" -H "X-Agent-ID: $NEW_ID" -H "X-Agent-Token: $NEW_TOKEN")"
  CW="$(http_code "$BASE/api/v1/agent/tasks" -H "X-Agent-ID: $NEW_ID" -H "X-Agent-Token: wrong-token")"
  if [ "$CT" = 200 ] && [ "$TASKS_OK" = 1 ] && [ "$CH" = 200 ] && [ "$CW" = 401 ]; then
    pass "W29-07 issued agent token works (tasks 200, heartbeat 200); wrong token 401"
  else fail "W29-07 tasks flow: tasks=$CT heartbeat=$CH wrong-token=$CW"; fi
else
  fail "W29-07 tasks flow skipped (no agent)"
fi

REV_PAIR="$(mint_token w29-07-revoke)"
REV_ID="${REV_PAIR% *}"; REV_TOK="${REV_PAIR#* }"
if [ -n "$REV_PAIR" ]; then
  CD="$(http_code -X DELETE "$BASE/api/v1/agent/enrollment-tokens/$REV_ID" -H "Authorization: Bearer uat-token")"
  CR="$(http_code -X POST "$REG_URL" -H "$JSON_H" -d "{\"name\":\"kk-uat-agent-rev\",\"type\":\"linux\",\"enrollment_token\":\"$REV_TOK\"}")"
  if [ "$CD" = 204 ] && { [ "$CR" = 401 ] || [ "$CR" = 403 ]; }; then pass "W29-07 revoked token refused (revoke 204, register $CR)"
  else fail "W29-07 revoked token: revoke=$CD register=$CR"; fi
else
  fail "W29-07 revoke case skipped (mint failed)"
fi

A_REG="$(curl -fsSk -H "Authorization: Bearer uat-token" "$BASE/api/v1/audit?action=agent.register&limit=100" 2>&1)"
A_REV="$(curl -fsSk -H "Authorization: Bearer uat-token" "$BASE/api/v1/audit?action=agent.token_revoke&limit=100" 2>&1)"
if printf '%s' "$A_REG" | grep -q '"outcome":"success"' && printf '%s' "$A_REG" | grep -q '"outcome":"denied"' \
   && printf '%s' "$A_REV" | grep -q '"action":"agent.token_revoke"'; then
  pass "W29-07 audit has agent.register success + denied and agent.token_revoke"
else fail "W29-07 audit missing rows: register=$A_REG revoke=$A_REV"; fi

if [ -n "$NEW_ID" ]; then
  C="$(http_code -X DELETE "$BASE/api/v1/agents/$NEW_ID" -H "Authorization: Bearer uat-token")"
  if [ "$C" = 204 ]; then pass "W29-07 cleanup: token-enrolled agent removed (204)"
  else fail "W29-07 cleanup: status $C"; fi
else
  fail "W29-07 cleanup skipped (no agent)"
fi

echo
echo "=== W19-04 summary: $PASS_COUNT passed, $FAIL_COUNT failed ==="
exit $((FAIL_COUNT > 0))
