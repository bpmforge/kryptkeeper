#!/usr/bin/env bash
# W30-19: a 600 s GET /api/v1/events stream through the SHIPPED nginx
# (nginx.conf, the dashboard service of docker-compose.yml) must not be
# buffered, timed out or dropped.
#
#   bash tests/live/sse/run.sh
#
# The stack is the repo's docker-compose.yml, run with podman compose in its
# own project. A generated override (kept in a temp dir, nothing committed)
# does two things only: bind-mounts THIS checkout's ./nginx.conf over the
# dashboard image's baked-in default.conf (so the file under test is the one
# on disk, not a stale image layer) and moves the published port to a free
# loopback port so it never collides with another stack.
#
# Images: by default the existing kryptkeeper:local and
# kryptkeeper-dashboard:local images are used (--no-build, works offline).
# KK_SSE_BUILD=1 rebuilds both from this checkout (needs registry access).
# NOTE: kryptkeeper:local must be built from a tree that has GET
# /api/v1/events (W30-13/14); the script fails fast if the hub answers 404.
#
# Duration: KK_SSE_SECONDS (default 600). Shorter values are for smoke runs
# only and do NOT satisfy the 10-minute acceptance.
#
# Secrets: the bootstrap token and keystore passphrase are generated per
# run, kept in the environment of the compose call, never printed.
set -u
set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/kk-uat-sse.XXXXXX")"
RUN_ID="$(openssl rand -hex 3)"
PROJECT="kk-uat-sse-${RUN_ID}"
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
WEB_PORT="$(free_port)"
WEB_BASE="http://127.0.0.1:${WEB_PORT}"
DURATION="${KK_SSE_SECONDS:-600}"
SCAN_EVERY=60
MAX_GAP=20
FIRST_HEARTBEAT_MAX=20
MIN_DATA_FRAMES=10
EVENTS_LOG="$WORK/events.log"
HEADERS="$WORK/headers.txt"

FAILED=0
STEP() { echo; echo "== $* =="; }
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }
DIE()  { echo "FAIL: $*"; exit 1; }

APP_BOOTSTRAP_TOKEN="uat-$(openssl rand -hex 16)"
KRYPTKEEPER_KEYSTORE_PASSPHRASE="uat-ks-$(openssl rand -hex 16)"
export APP_BOOTSTRAP_TOKEN KRYPTKEEPER_KEYSTORE_PASSPHRASE
export KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true

COMPOSE=(podman compose -p "$PROJECT" -f "$REPO_ROOT/docker-compose.yml" -f "$WORK/compose.override.yml")
CURL_PID=""
cleanup() {
  STEP "cleanup"
  [ -n "$CURL_PID" ] && kill "$CURL_PID" 2>/dev/null || true
  "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
  if [ -n "${KK_UAT_KEEP:-}" ]; then
    echo "KK_UAT_KEEP set -- leaving $WORK in place"
  else
    rm -rf "$WORK"
  fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 0. Preconditions and compose override.
# ---------------------------------------------------------------------------
STEP "preconditions"
for bin in podman curl python3 openssl; do
  command -v "$bin" >/dev/null 2>&1 || DIE "required tool not found: $bin"
done
[ -f "$REPO_ROOT/nginx.conf" ] || DIE "missing $REPO_ROOT/nginx.conf"
grep -q 'location = /api/v1/events' "$REPO_ROOT/nginx.conf" || DIE "nginx.conf has no 'location = /api/v1/events' block (W30-19 not applied)"
cat >"$WORK/compose.override.yml" <<EOF
services:
  kryptkeeper:
    ports: !reset []
  dashboard:
    ports: !override
      - "127.0.0.1:${WEB_PORT}:8080"
    volumes:
      - ${REPO_ROOT}/nginx.conf:/etc/nginx/conf.d/default.conf:ro
EOF
PASS "override written (dashboard published on 127.0.0.1:${WEB_PORT}, nginx.conf bind-mounted)"

# ---------------------------------------------------------------------------
# 1. Bring the stack up.
# ---------------------------------------------------------------------------
STEP "podman compose up (project $PROJECT)"
if [ "${KK_SSE_BUILD:-}" = "1" ]; then
  "${COMPOSE[@]}" up -d --build >"$WORK/compose-up.log" 2>&1 || { tail -20 "$WORK/compose-up.log"; DIE "compose up --build failed"; }
else
  "${COMPOSE[@]}" up -d --no-build >"$WORK/compose-up.log" 2>&1 || { tail -20 "$WORK/compose-up.log"; DIE "compose up --no-build failed (missing local images? set KK_SSE_BUILD=1)"; }
fi
tries=90
# /readyz is proxied by nginx to the hub over verified TLS, so a 200 here also
# proves the CA bundle export and the proxy's TLS verification work.
until curl -sS -f -o /dev/null "${WEB_BASE}/readyz" 2>/dev/null; do
  tries=$((tries - 1))
  [ $tries -le 0 ] && { "${COMPOSE[@]}" logs --tail 30 2>&1 | sed 's/^/  | /'; DIE "stack never answered ${WEB_BASE}/readyz"; }
  sleep 2
done
PASS "stack up; ${WEB_BASE}/readyz 200 through nginx"

code="$(curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${APP_BOOTSTRAP_TOKEN}" --max-time 3 "${WEB_BASE}/api/v1/events" 2>/dev/null)"
# --max-time kills a healthy stream (curl exit 28, code 200); only 404/401/5xx are fatal here.
case "$code" in
  200) ;;
  404) DIE "GET /api/v1/events is 404: kryptkeeper:local predates W30-13/14 (rebuild with KK_SSE_BUILD=1)" ;;
  *) DIE "GET /api/v1/events returned HTTP $code before the soak" ;;
esac

# ---------------------------------------------------------------------------
# 2. The soak: timestamped stream capture + one scan POST per minute.
# ---------------------------------------------------------------------------
STEP "open the stream for ${DURATION}s (scan POST every ${SCAN_EVERY}s)"
T0="$(python3 -c 'import time; print(f"{time.time():.3f}")')"
curl -sN -D "$HEADERS" -H "Authorization: Bearer ${APP_BOOTSTRAP_TOKEN}" "${WEB_BASE}/api/v1/events" \
  | python3 -u -c '
import sys, time
for line in sys.stdin:
    print("%.3f %s" % (time.time(), line.rstrip("\n")), flush=True)
' >"$EVENTS_LOG" &
CURL_PID=$!

elapsed=0
scans_ok=0
next_scan=5
while [ "$elapsed" -lt "$DURATION" ]; do
  sleep 1; elapsed=$((elapsed + 1))
  if [ "$elapsed" -ge "$next_scan" ]; then
    next_scan=$((next_scan + SCAN_EVERY))
    # Two scans per tick: one queued-event frame each, so the >=10 data-frame
    # bar has margin instead of sitting exactly on 10 posts in 600 s.
    for _ in 1 2; do
      sc="$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${WEB_BASE}/api/v1/discovery/scans" \
        -H "Authorization: Bearer ${APP_BOOTSTRAP_TOKEN}" -H 'Content-Type: application/json' \
        -d '{"scan_type":"fast","target":"10.0.0.0/30"}' 2>/dev/null)"
      case "$sc" in 2??) scans_ok=$((scans_ok + 1)) ;; esac
    done
    echo "  t=${elapsed}s scan POST -> HTTP ${sc} (ok so far: ${scans_ok}); stream lines: $(wc -l <"$EVENTS_LOG" | tr -d ' ')"
  fi
done

# Still connected at t=DURATION: the capture pipeline is alive.
STREAM_ALIVE=0
kill -0 "$CURL_PID" 2>/dev/null && STREAM_ALIVE=1
T_END="$(python3 -c 'import time; print(f"{time.time():.3f}")')"
kill "$CURL_PID" 2>/dev/null || true
wait "$CURL_PID" 2>/dev/null || true
CURL_PID=""

# ---------------------------------------------------------------------------
# 3. Assertions.
# ---------------------------------------------------------------------------
STEP "assertions"
[ "$STREAM_ALIVE" = "1" ] && PASS "curl still connected at t=${DURATION}s (no 504 / premature close)" \
  || FAIL "stream was closed before t=${DURATION}s"

python3 - "$EVENTS_LOG" "$T0" "$T_END" "$MAX_GAP" "$FIRST_HEARTBEAT_MAX" "$MIN_DATA_FRAMES" <<'PY'
import sys
log, t0, t_end, max_gap, first_hb_max, min_data = sys.argv[1], float(sys.argv[2]), float(sys.argv[3]), float(sys.argv[4]), float(sys.argv[5]), int(sys.argv[6])
rows = []
with open(log) as f:
    for line in f:
        ts, _, text = line.rstrip("\n").partition(" ")
        if text.strip():
            rows.append((float(ts), text))
fail = False
def check(ok, msg):
    global fail
    print(("PASS: " if ok else "FAIL: ") + msg)
    if not ok:
        fail = True
hb = [t for t, x in rows if x.startswith(": heartbeat")]
data = [t for t, x in rows if x.startswith("data:")]
check(bool(hb) and hb[0] - t0 <= first_hb_max, "first ': heartbeat' %s s after connect (limit %.0f)" % (("%.1f" % (hb[0] - t0)) if hb else "never", first_hb_max))
times = [t for t, _ in rows]
gaps = [b - a for a, b in zip(times, times[1:])]
gaps.append(t_end - times[-1]) if times else None
mg = max(gaps) if gaps else float("inf")
check(mg <= max_gap, "largest gap between received lines %.1f s (limit %.0f); %d heartbeats, %d data lines" % (mg, max_gap, len(hb), len(data)))
check(len(data) >= min_data, "%d data: frames (need >= %d)" % (len(data), min_data))
sys.exit(1 if fail else 0)
PY
[ $? -eq 0 ] || FAILED=1

ctype="$(grep -i '^content-type:' "$HEADERS" | head -1 | tr -d '\r' | awk '{print tolower($2)}')"
case "$ctype" in text/event-stream*) PASS "Content-Type: $ctype" ;; *) FAIL "Content-Type is '${ctype}', want text/event-stream" ;; esac
xab="$(grep -i '^x-accel-buffering:' "$HEADERS" | head -1 | tr -d '\r' | awk '{print tolower($2)}')"
if [ -z "$xab" ] || [ "$xab" = "no" ]; then PASS "X-Accel-Buffering: ${xab:-absent}"; else FAIL "X-Accel-Buffering is '${xab}'"; fi
[ "$scans_ok" -ge 1 ] && PASS "$scans_ok scan POST(s) accepted" || FAIL "no scan POST was accepted (no events were generated)"
[ "$DURATION" -ge 600 ] && PASS "full ${DURATION}s soak" || echo "NOTE: KK_SSE_SECONDS=${DURATION} < 600 -- smoke run, does NOT satisfy acceptance 3"

STEP "result"
if [ "$FAILED" -eq 0 ]; then
  echo "ALL PASS"
  exit 0
fi
echo "ONE OR MORE STEPS FAILED (rerun with KK_UAT_KEEP=1 to keep $WORK)"
exit 1
