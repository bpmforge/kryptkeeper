#!/usr/bin/env bash
# W24-01: seeded TLS discovery corpus with recall / false-positive harness.
#
# 43 known endpoints (TLS 1.0-1.3, self-signed, expired, ML-KEM hybrid,
# SNI-only, plain HTTP on 443) are served by corpusd on a private /24; a
# containerised hub scans the /24 (timed fast scan, then full scan) and
# compare.py checks what discovery stored against ground-truth.json.
# Also proves a scan of an egress-denied address is refused and audited.
#
# Podman only. PASS/FAIL per step, non-zero exit on any FAIL, trap cleanup.
# KK_EVIDENCE_DIR receives report.json, scan.json, audit.json.
# KK_SOURCE_ONLY=1 sources the functions without running main (W24-07).
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib/podman.sh"
set -u
set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
# shellcheck disable=SC1091
. "$HERE/../podman-host.sh"
WORK="$(mktemp -d /tmp/kk-uat-disc.XXXXXX)"
RUN_ID="$(openssl rand -hex 3)"
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
HUB_PORT="$(free_port)"
HUB_BASE="http://127.0.0.1:${HUB_PORT}"
TOKEN=uat-token
FIX_IMAGE="localhost/kk-uat-corpus:$RUN_ID"
HUB_IMAGE="localhost/kk-uat-disc-hub:$RUN_ID"
NET="kk-uat-disc-net-$RUN_ID"
FIX_CTR="kk-uat-corpus-$RUN_ID"
HUB_CTR="kk-uat-disc-hub-$RUN_ID"
PREFIX=""
FAST_SECONDS=""

FAILED=0
STEP() { echo; echo "== $* =="; }
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }
DIE()  { echo "FAIL: $*"; cleanup; exit 1; }

cleanup() {
  STEP "cleanup"
  kk_rm "$FIX_CTR" "$HUB_CTR"
  podman network rm "$NET" >/dev/null 2>&1 || true
  podman rmi -f "$FIX_IMAGE" "$HUB_IMAGE" >/dev/null 2>&1 || true
  rm -f "$HERE/corpusd/corpusd"
  rm -rf "$WORK"
}

curlj() { curl -sS -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' "$@"; }

setup_network() {
  STEP "private /24 network"
  local try
  for try in 1 2 3 4 5; do
    PREFIX="10.$((RANDOM % 100 + 100)).$((RANDOM % 250))"
    if podman network create --subnet "$PREFIX.0/24" "$NET" >/dev/null 2>&1; then
      PASS "network $NET on $PREFIX.0/24"; return 0
    fi
  done
  DIE "could not create a non-overlapping /24 after 5 tries"
}

start_fixture() {
  STEP "build and start corpusd fixture"
  GOARCH="$(kk_goarch)"
  ( cd "$HERE/corpusd" && CGO_ENABLED=0 GOOS=linux GOARCH=$GOARCH go build -o corpusd . ) \
    && PASS "corpusd built (linux/$GOARCH)" || DIE "corpusd build failed"
  podman build -t "$FIX_IMAGE" "$HERE" >"$WORK/build-fix.log" 2>&1 \
    && PASS "fixture image built" || DIE "fixture image build failed, see $WORK/build-fix.log"
  local ips="" i
  for i in $(seq 11 53); do ips="$ips $PREFIX.$i"; done
  mkdir -p "$WORK/out"  # bind mounts under /tmp are not visible to the podman VM on macOS: read via exec instead
  podman run -d --name "$FIX_CTR" --network "$NET" --ip "$PREFIX.10" --cap-add NET_ADMIN \
    -e CORPUS_PREFIX="$PREFIX" -e CORPUS_IPS="$ips" "$FIX_IMAGE" >/dev/null \
    && PASS "fixture container up at $PREFIX.10" || DIE "failed to start fixture"
  local tries=30 n
  while [ $tries -gt 0 ]; do
    podman exec "$FIX_CTR" cat /out/served.json >"$WORK/out/served.json" 2>/dev/null
    n="$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' "$WORK/out/served.json" 2>/dev/null || echo 0)"
    [ "$n" -ge 43 ] && break
    tries=$((tries - 1)); sleep 1
  done
  if [ "$n" -ge 43 ]; then PASS "served.json has $n endpoints"; else
    podman logs "$FIX_CTR" 2>&1 | tail -20; DIE "served.json never reached 43 entries (got $n)"; fi
}

# start_hub [extra hub.env lines...]
start_hub() {
  STEP "build and start hub"
  mkdir -p "$WORK/hubctx"
  ( cd "$REPO_ROOT" && GOOS=linux GOARCH=$GOARCH CGO_ENABLED=0 go build -o "$WORK/hubctx/kryptkeeper" ./cmd/kryptkeeper ) \
    && PASS "hub built (linux/$GOARCH)" || DIE "go build failed"
  cp "$REPO_ROOT/tests/live/autopilot/hub.Containerfile" "$WORK/hubctx/Containerfile"
  podman build -t "$HUB_IMAGE" "$WORK/hubctx" >"$WORK/build-hub.log" 2>&1 \
    && PASS "hub image built" || DIE "hub image build failed, see $WORK/build-hub.log"
  cat >"$WORK/hub.env" <<ENV
APP_BOOTSTRAP_TOKEN=$TOKEN
AUTH_MODE=bootstrap
APP_CERTIFICATE_PROVIDER=ca
APP_DISCOVERY_PROVIDER=db
APP_NOTIFICATION_PROVIDER=file
KRYPTKEEPER_TLS_DISABLE=true
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
KRYPTKEEPER_DISCOVERY_DENY_CIDRS=$PREFIX.200/32
KRYPTKEEPER_DISCOVERY_MAX_TARGETS=65536
ENV
  local line
  for line in "$@"; do echo "$line" >>"$WORK/hub.env"; done
  podman run -d --name "$HUB_CTR" --network "$NET" -p "127.0.0.1:${HUB_PORT}:${HUB_PORT}" \
    --env-file "$WORK/hub.env" "$HUB_IMAGE" >/dev/null \
    && PASS "hub container up" || DIE "failed to start the hub container"
  local tries=40
  until curl -sS -f -o /dev/null "${HUB_BASE}/api/v1/cas" -H "Authorization: Bearer ${TOKEN}"; do
    tries=$((tries - 1)); [ $tries -le 0 ] && { podman logs "$HUB_CTR" 2>&1 | tail -20; DIE "hub never answered /api/v1/cas"; }
    sleep 1
  done
  PASS "hub answering on $HUB_BASE"
}

# wait_scan <job id> <timeout seconds>: poll until the job leaves queued/running.
wait_scan() {
  local id=$1 timeout=$2 t0 st
  t0=$(date +%s)
  while [ $(( $(date +%s) - t0 )) -lt "$timeout" ]; do
    st="$(curlj "${HUB_BASE}/api/v1/discovery/scan-jobs?limit=50" | python3 -c '
import json,sys
id=sys.argv[1]
for j in json.load(sys.stdin)["data"]["scan_jobs"]:
    if j["id"]==id: print(j["status"]); break
' "$id" 2>/dev/null)"
    case "$st" in queued|running|"") sleep 2 ;; *) echo "$st"; return 0 ;; esac
  done
  echo timeout; return 1
}

create_scan() { # body -> prints job id
  curlj -X POST "${HUB_BASE}/api/v1/discovery/scans" -d "$1" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["scan_job"]["id"])' 2>/dev/null
}

dump_endpoints() { # out file: pages /discovery/endpoints
  python3 - "$HUB_BASE" "$TOKEN" "$1" <<'PY'
import json, sys, urllib.request
hub, token, out = sys.argv[1:4]
rows, cursor = [], ""
while True:
    url = hub + "/api/v1/discovery/endpoints?limit=100" + ("&cursor=" + str(cursor) if cursor != "" else "")
    d = json.load(urllib.request.urlopen(urllib.request.Request(url, headers={"Authorization": "Bearer " + token})))
    rows += d["data"]["endpoints"]
    cursor = (d.get("meta") or {}).get("next_cursor")
    if cursor is None:
        break
json.dump(rows, open(out, "w"))
print(len(rows))
PY
}

dump_audit() { # out file
  python3 - "$HUB_BASE" "$TOKEN" "$1" <<'PY'
import json, sys, urllib.request
hub, token, out = sys.argv[1:4]
rows, cursor = [], ""
while True:
    url = hub + "/api/v1/audit?limit=100" + ("&cursor=" + cursor if cursor else "")
    d = json.load(urllib.request.urlopen(urllib.request.Request(url, headers={"Authorization": "Bearer " + token})))
    rows += d["data"]
    cursor = (d.get("meta") or {}).get("next_cursor") or ""
    if not cursor:
        break
json.dump(rows, open(out, "w"))
sys.exit(0 if rows else 1)
PY
}

main() {
  trap cleanup EXIT
  setup_network
  start_fixture
  start_hub

  STEP "fast /24 scan (acceptance 3: <= 300 s)"
  local t0 id st
  t0=$(date +%s)
  id="$(create_scan "{\"scan_type\":\"fast\",\"target\":\"$PREFIX.0/24\"}")"
  [ -n "$id" ] || DIE "fast scan was not created"
  st="$(wait_scan "$id" 330)"
  FAST_SECONDS=$(( $(date +%s) - t0 ))
  echo "  fast scan status=$st elapsed=${FAST_SECONDS}s"
  case "$st" in completed|completed_with_errors) PASS "fast scan finished ($st)" ;; *) FAIL "fast scan ended $st" ;; esac
  if [ "$FAST_SECONDS" -le 300 ]; then PASS "fast /24 scan took ${FAST_SECONDS}s (<= 300)"; else FAIL "fast /24 scan took ${FAST_SECONDS}s (> 300)"; fi

  STEP "full scans over .0/27 and .32/27 with ports 8443, 9443 (acceptance 2)"
  local half
  for half in 0 32; do
    id="$(create_scan "{\"scan_type\":\"full\",\"target\":\"$PREFIX.$half/27\",\"ports\":[8443,9443]}")"
    [ -n "$id" ] || DIE "full scan $PREFIX.$half/27 was not created"
    st="$(wait_scan "$id" 600)"
    case "$st" in completed|completed_with_errors) PASS "full scan $PREFIX.$half/27 finished ($st)" ;; *) FAIL "full scan $PREFIX.$half/27 ended $st" ;; esac
  done
  local n
  n="$(dump_endpoints "$WORK/scan.json")" && PASS "paged $n endpoints into scan.json" || DIE "could not page endpoints"

  STEP "compare against ground truth"
  python3 "$HERE/compare.py" "$HERE/ground-truth.json" "$WORK/scan.json" "$WORK/out/served.json" \
    "$PREFIX" "$WORK/report.json" "$FAST_SECONDS" && PASS "recall / false-positive / posture thresholds met" \
    || FAIL "corpus comparison failed thresholds (see table above)"

  STEP "egress-denied target refused and audited (acceptance 4)"
  local resp code
  resp="$(curlj -o "$WORK/denied.body" -w '%{http_code}' -X POST "${HUB_BASE}/api/v1/discovery/scans" \
    -d "{\"scan_type\":\"fast\",\"target\":\"$PREFIX.200\"}")"
  if [ "$resp" = 400 ] && grep -q 'denied network range' "$WORK/denied.body"; then
    PASS "denied target refused: HTTP 400 denied network range"
  else
    FAIL "denied target: HTTP $resp body=$(cat "$WORK/denied.body")"
  fi
  if dump_audit "$WORK/audit.json" && python3 - "$WORK/audit.json" <<'PY'
import json, sys
rows = json.load(open(sys.argv[1]))
hit = [r for r in rows if r.get("action") == "discovery.scan.create" and r.get("outcome") == "failure"
       and r.get("resource_type") == "discovery" and r.get("actor_id")]
sys.exit(0 if hit else 1)
PY
  then PASS "audit has discovery.scan.create outcome=failure for the refused scan"
  else FAIL "no discovery.scan.create failure entry in the audit trail"; fi

  if [ -n "${KK_EVIDENCE_DIR:-}" ]; then
    mkdir -p "$KK_EVIDENCE_DIR"
    cp "$WORK/report.json" "$WORK/scan.json" "$WORK/audit.json" "$KK_EVIDENCE_DIR/" 2>/dev/null || true
  fi
  STEP "result"
  if [ "$FAILED" -eq 0 ]; then echo "ALL PASS"; exit 0; fi
  echo "ONE OR MORE STEPS FAILED (hub logs: podman logs $HUB_CTR)"; exit 1
}

if [ "${KK_SOURCE_ONLY:-0}" != 1 ]; then main; fi
