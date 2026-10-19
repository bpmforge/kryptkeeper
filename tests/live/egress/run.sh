#!/usr/bin/env bash
# W30-20 live UAT: zero default egress. Hub + agent run in a podman pod with
# NO network (loopback only); DNS and TCP 80/443 land on an in-pod tripwire sink
# (sink.py) that records every hostname. strace records every non-loopback
# connect(). Any host not in docs/ops/DATA_RESIDENCY.md fails the run.
#
#   run.sh [--short|--soak] [--ct [--second-source]] [--inject-unlisted] [--minutes N]
#
#   --short            10-minute capture (default)
#   --soak             25 h wall-clock capture, every scheduler at 1 minute
#   --ct               KRYPTKEEPER_CT_DOMAINS=example.org, Cert Spotter OFF  => exactly {crt.sh}
#   --second-source    with --ct: Cert Spotter ON                            => crt.sh + api.certspotter.com
#   --inject-unlisted  self-test: the sink is asked for unlisted.invalid; the run MUST exit non-zero
#   --minutes N        override the window length
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib/podman.sh"
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
HERE="$ROOT/tests/live/egress"
RESIDENCY="$ROOT/docs/ops/DATA_RESIDENCY.md"

MODE=short; CT=0; SECOND=0; INJECT=0; MINUTES=""
while [ $# -gt 0 ]; do
  case "$1" in
    --short) MODE=short ;;
    --soak) MODE=soak ;;
    --ct) CT=1 ;;
    --second-source) SECOND=1 ;;
    --inject-unlisted) INJECT=1 ;;
    --minutes) MINUTES="${2:?--minutes needs a value}"; shift ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
  shift
done
if [ "$SECOND" = 1 ] && [ "$CT" = 0 ]; then echo "--second-source needs --ct" >&2; exit 2; fi

if [ -z "$MINUTES" ]; then
  if [ "$MODE" = soak ]; then MINUTES=1500
  elif [ "$CT" = 1 ]; then MINUTES=65   # the CT monitor's first tick is KRYPTKEEPER_CT_SCAN_HOURS (min 1 h) after boot
  elif [ "$INJECT" = 1 ]; then MINUTES=1
  else MINUTES=10; fi
fi

# podman machine on macOS only virtiofs-mounts $HOME, so the work dir lives there.
WORK="$(mktemp -d "$HOME/.kk-uat-egress.XXXXXX")"
RUN_ID="$(openssl rand -hex 3)"
POD="kk-egress-$RUN_ID"
IMAGE="localhost/kk-egress:$RUN_ID"
ARTIFACTS="${EGRESS_ARTIFACT_DIR:-$HERE/out}"
HUB_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
PASS_COUNT=0; FAIL_COUNT=0

log()  { printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*"; }
pass() { PASS_COUNT=$((PASS_COUNT+1)); log "PASS: $*"; }
fail() { FAIL_COUNT=$((FAIL_COUNT+1)); log "FAIL: $*"; }

# shellcheck disable=SC2329 # invoked via trap
cleanup() {
  log "cleaning up"
  mkdir -p "$ARTIFACTS"
  cp "$WORK"/out/observed.jsonl "$WORK"/out/connect*.log "$WORK"/out/verdict.txt "$ARTIFACTS"/ 2>/dev/null || true
  podman pod rm -f "$POD" >/dev/null 2>&1 || true
  podman rmi -f "$IMAGE" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

command -v podman >/dev/null || { fail "podman not found"; exit 1; }
[ -f "$RESIDENCY" ] || { fail "missing $RESIDENCY"; exit 1; }

# --- expected host set, parsed from the residency doc (never hard-coded) ---
HOSTS_BLOCK="$(awk '/<!-- egress-hosts:begin -->/{f=1;next} /<!-- egress-hosts:end -->/{f=0} f && NF' "$RESIDENCY")"
[ -n "$HOSTS_BLOCK" ] || { fail "no egress-hosts block in $RESIDENCY"; exit 1; }
if [ "$CT" = 0 ]; then
  EXPECTED="$(awk -F'|' '$2=="default"{print $3}' <<<"$HOSTS_BLOCK" | sort -u)"
elif [ "$SECOND" = 1 ]; then
  EXPECTED="$(awk -F'|' '$2=="KRYPTKEEPER_CT_DOMAINS"{print $3}' <<<"$HOSTS_BLOCK" | sort -u)"
else
  EXPECTED="$(awk -F'|' '$2=="KRYPTKEEPER_CT_DOMAINS" && $1=="ct"{print $3}' <<<"$HOSTS_BLOCK" | sort -u)"
fi
if [ "$CT" = 1 ] && [ -z "$EXPECTED" ]; then fail "no CT rows in the residency block"; exit 1; fi
log "mode=$MODE ct=$CT second-source=$SECOND inject=$INJECT window=${MINUTES}min; expected hosts: ${EXPECTED:-<none>}"

GOARCH="$(kk_goarch)"

# --- everything that touches the network happens BEFORE the capture window ---
mkdir -p "$WORK/bin" "$WORK/out" "$WORK/scan"
(cd "$ROOT" && GOOS=linux GOARCH="$GOARCH" CGO_ENABLED=0 go build -o "$WORK/bin/kryptkeeper" ./cmd/kryptkeeper \
  && GOOS=linux GOARCH="$GOARCH" CGO_ENABLED=0 go build -o "$WORK/bin/kryptkeeper-agent" ./cmd/kryptkeeper-agent) \
  || { fail "go build (GOARCH=$GOARCH)"; exit 1; }
pass "built hub and agent for linux/$GOARCH"

if ! podman build -t "$IMAGE" -f - "$WORK" >"$WORK/build.log" 2>&1 <<'EOF'
FROM docker.io/library/debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 strace curl openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
EOF
then fail "podman build (see below)"; cat "$WORK/build.log"; exit 1; fi
pass "built sink image"

printf 'nameserver 127.0.0.1\n' >"$WORK/resolv.conf"
cp "$HERE/sink.py" "$WORK/sink.py"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -keyout "$WORK/scan/leaf.key" -out "$WORK/scan/leaf.pem" \
  -days 30 -nodes -subj "/CN=egress-uat.invalid" >/dev/null 2>&1 || { fail "generate scan fixture cert"; exit 1; }

# --- pod: loopback only, so real external traffic is impossible ---
podman pod rm -f "$POD" >/dev/null 2>&1 || true
podman pod create --name "$POD" --network none >/dev/null || { fail "pod create --network none"; exit 1; }
COMMON=(--pod "$POD" -v "$WORK/out:/out" -v "$WORK/resolv.conf:/etc/resolv.conf:ro")

podman run -d --name "sink-$RUN_ID" "${COMMON[@]}" -v "$WORK/sink.py:/sink.py:ro" "$IMAGE" python3 /sink.py >/dev/null \
  || { fail "start sink"; exit 1; }
for _ in $(seq 1 20); do [ -f "$WORK/out/sink.ready" ] && break; sleep 1; done
[ -f "$WORK/out/sink.ready" ] || { fail "sink never became ready"; podman logs "sink-$RUN_ID" 2>&1 | tail -20; exit 1; }
pass "tripwire sink listening on :53/:80/:443 inside the pod"
sx() { podman exec "sink-$RUN_ID" "$@"; }

# --- default config = tests/live/agent/run.sh's env, plus forced schedulers ---
{
  cat <<EOF
APP_BOOTSTRAP_TOKEN=uat-token
AUTH_MODE=bootstrap
APP_CERTIFICATE_PROVIDER=ca
APP_DISCOVERY_PROVIDER=db
APP_NOTIFICATION_PROVIDER=file
KRYPTKEEPER_TLS_SANS=localhost,127.0.0.1
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
APP_BIND_ADDR=127.0.0.1
PORT=$HUB_PORT
KRYPTKEEPER_AGENT_ENROLLMENT_SECRETS=uat-enrollment-secret
KRYPTKEEPER_BASE_URL=https://127.0.0.1:$HUB_PORT
RENEWAL_POLL_MINUTES=1
KRYPTKEEPER_SLO_SWEEP_MINUTES=1
KRYPTKEEPER_ANOMALY_SWEEP_MINUTES=1
KRYPTKEEPER_MESH_SWEEP_MINUTES=1
KRYPTKEEPER_EXCEPTION_EXPIRY_SWEEP_MINUTES=1
KRYPTKEEPER_OWNERSHIP_ORPHAN_SWEEP_MINUTES=1
AGENT_RENEWAL_SWEEP_MINUTES=1
EOF
  if [ "$CT" = 1 ]; then
    echo "KRYPTKEEPER_CT_DOMAINS=example.org"
    echo "KRYPTKEEPER_CT_SCAN_HOURS=1"
    [ "$SECOND" = 1 ] || echo "KRYPTKEEPER_CT_SECOND_SOURCE=off"
  fi
} >"$WORK/hub.env"

podman run -d --name "hub-$RUN_ID" "${COMMON[@]}" --cap-add SYS_PTRACE --env-file "$WORK/hub.env" \
  -v "$WORK/bin/kryptkeeper:/usr/local/bin/kryptkeeper:ro" "$IMAGE" \
  strace -f -qq -e trace=connect -o /out/connect-hub.log /usr/local/bin/kryptkeeper >/dev/null \
  || { fail "start hub"; exit 1; }

BASE="https://127.0.0.1:$HUB_PORT"
for _ in $(seq 1 40); do sx curl -fsSk "$BASE/healthz" >/dev/null 2>&1 && break; sleep 1; done
sx curl -fsSk "$BASE/healthz" >/dev/null 2>&1 || { fail "hub never became healthy"; podman logs "hub-$RUN_ID" 2>&1 | tail -30; exit 1; }
pass "hub healthy under strace"

sx curl -sSk --max-time 5 -o /out/cacerts.b64 "$BASE/.well-known/est/cacerts" \
  && openssl base64 -d -A -in "$WORK/out/cacerts.b64" -out "$WORK/cacerts.p7" \
  && openssl pkcs7 -inform der -in "$WORK/cacerts.p7" -print_certs -out "$WORK/hub-ca.pem" \
  && [ -s "$WORK/hub-ca.pem" ] || { fail "could not export the hub CA"; exit 1; }

REG="$(sx curl -fsSk -X POST "$BASE/api/v1/agent/register" -H 'Content-Type: application/json' \
  -d '{"name":"kk-egress-agent","type":"linux","enrollment_secret":"uat-enrollment-secret"}')"
AGENT_ID="$(grep -o '"agent_id":"[^"]*"' <<<"$REG" | cut -d'"' -f4)"
AGENT_TOKEN="$(grep -o '"token":"[^"]*"' <<<"$REG" | cut -d'"' -f4)"
[ -n "$AGENT_ID" ] && [ -n "$AGENT_TOKEN" ] || { fail "agent registration failed: $REG"; exit 1; }

podman run -d --name "agent-$RUN_ID" "${COMMON[@]}" --cap-add SYS_PTRACE \
  -v "$WORK/bin/kryptkeeper-agent:/usr/local/bin/kryptkeeper-agent:ro" \
  -v "$WORK/hub-ca.pem:/etc/kryptkeeper/hub-ca.pem:ro" -v "$WORK/scan:/opt/scan:ro" \
  -e KRYPTKEEPER_HUB_URL="$BASE" -e KRYPTKEEPER_HUB_CA_CERT_FILE=/etc/kryptkeeper/hub-ca.pem \
  -e KRYPTKEEPER_AGENT_ID="$AGENT_ID" -e KRYPTKEEPER_AGENT_TOKEN="$AGENT_TOKEN" \
  -e KRYPTKEEPER_AGENT_NAME=kk-egress-agent -e KRYPTKEEPER_POLL_INTERVAL=8 -e KRYPTKEEPER_SCAN_PATHS=/opt/scan \
  "$IMAGE" strace -f -qq -e trace=connect -o /out/connect-agent.log /usr/local/bin/kryptkeeper-agent >/dev/null \
  || { fail "start agent"; exit 1; }

ACTIVE=""
for _ in $(seq 1 20); do
  if sx curl -fsSk -H "Authorization: Bearer uat-token" "$BASE/api/v1/agents" \
      | python3 -c "
import json,sys
d=json.load(sys.stdin)
sys.exit(0 if any(a.get('id')=='$AGENT_ID' and a.get('status')=='active' and a.get('inventory_count',0)>=1 for a in d.get('agents',[])) else 1)" 2>/dev/null; then
    ACTIVE=1; break
  fi
  sleep 2
done
if [ -n "$ACTIVE" ]; then pass "agent registered, active, inventory pushed (default config exercised)"
else fail "agent never showed active with inventory; the capture would prove nothing"; fi

# --- capture window (starts only now) ---
if [ "$INJECT" = 1 ]; then
  sx python3 -c "import socket; socket.gethostbyname('unlisted.invalid')" >/dev/null 2>&1 || true
  log "injected one lookup for unlisted.invalid"
fi
END=$(( $(date +%s) + MINUTES * 60 ))
log "capture window: ${MINUTES} min"
while [ "$(date +%s)" -lt "$END" ]; do
  for c in hub agent; do
    [ "$(podman inspect -f '{{.State.Running}}' "$c-$RUN_ID" 2>/dev/null)" = true ] || { fail "$c container exited mid-window"; podman logs "$c-$RUN_ID" 2>&1 | tail -20; END=0; }
  done
  [ "$END" = 0 ] && break
  sleep 30
done
podman stop -t 5 "agent-$RUN_ID" "hub-$RUN_ID" >/dev/null 2>&1 || true
log "hub log tail:"; podman logs "hub-$RUN_ID" 2>&1 | tail -5

# --- verdict ---
python3 - "$WORK/out" "$POD" "$RUN_ID" >"$WORK/out/verdict.txt" <<'EOF'
import json, re, sys, ipaddress, glob
out, pod, rid = sys.argv[1:4]
internal = {"localhost", pod, f"hub-{rid}", f"agent-{rid}", f"sink-{rid}"}
hosts = set()
try:
    for line in open(f"{out}/observed.jsonl"):
        h = json.loads(line)["host"].lower().rstrip(".")
        if h not in internal:
            hosts.add(h)
except FileNotFoundError:
    pass
bad = []
for path in sorted(glob.glob(f"{out}/connect-*.log")):
    for line in open(path):
        for m in re.finditer(r'inet_addr\("([^"]+)"\)|inet_pton\(AF_INET6, "([^"]+)"', line):
            a = ipaddress.ip_address(m.group(1) or m.group(2))
            if not a.is_loopback:
                bad.append(f"{path.rsplit('/',1)[1]}: {line.strip()}")
print("HOSTS " + "\n".join(sorted(hosts)))
print("BAD " + "\n".join(bad))
EOF
OBSERVED="$(sed -n '/^HOSTS /,/^BAD /p' "$WORK/out/verdict.txt" | sed -e '/^BAD /d' -e 's/^HOSTS //' | awk 'NF' | sort -u)"
BADCONN="$(sed -n '/^BAD /,$p' "$WORK/out/verdict.txt" | sed 's/^BAD //' | awk 'NF')"

if [ "$OBSERVED" = "$EXPECTED" ]; then
  pass "observed hosts == expected (${EXPECTED:-none}), 0 differences"
else
  fail "observed hosts differ from the residency list"
  diff <(printf '%s\n' "$EXPECTED" | awk 'NF') <(printf '%s\n' "$OBSERVED" | awk 'NF') || true
fi
if [ -z "$BADCONN" ]; then pass "0 non-loopback connect() calls"
else fail "non-loopback connect() calls:"; printf '%s\n' "$BADCONN"; fi

echo
echo "=== W30-20 egress summary: $PASS_COUNT passed, $FAIL_COUNT failed (mode=$MODE ct=$CT second=$SECOND inject=$INJECT ${MINUTES}min) ==="
exit $((FAIL_COUNT > 0))
