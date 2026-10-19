#!/usr/bin/env bash
# W24-07: unattended scheduled discovery. The hub is started with a 1m scan
# interval and one target; no operator POSTs a scan. The case passes when an
# endpoint appears and its last_seen_at then advances (T1 -> T2) on a later
# scheduler tick. Needs the W24-01 fixture (run.sh), podman only (~3-4 min).
# KK_EVIDENCE_DIR receives schedule.json and audit-scan-create.json.
set -u -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KK_SOURCE_ONLY=1
# shellcheck disable=SC1091
. "$HERE/run.sh"
trap cleanup EXIT

poll_endpoint() { # <ip> -> prints last_seen_at of the :443 endpoint, empty if absent
  curlj "${HUB_BASE}/api/v1/discovery/endpoints?limit=100" | python3 -c '
import json, sys
for e in json.load(sys.stdin)["data"]["endpoints"]:
    if e.get("hostname") == sys.argv[1] and e.get("port") == 443 and e.get("last_seen_at"):
        print(e["last_seen_at"]); break
' "$1" 2>/dev/null
}

# newer <a> <b>: exit 0 when RFC 3339 instant a is strictly after b.
newer() {
  python3 - "$1" "$2" <<'PY'
import sys
from datetime import datetime
p = lambda s: datetime.fromisoformat(s.replace("Z", "+00:00"))
sys.exit(0 if p(sys.argv[1]) > p(sys.argv[2]) else 1)
PY
}

setup_network
start_fixture
start_hub "KRYPTKEEPER_DISCOVERY_SCAN_INTERVAL=1m" "KRYPTKEEPER_DISCOVERY_SCAN_TARGETS=$PREFIX.11"
TARGET="$PREFIX.11"

STEP "T1: first scheduled scan records the endpoint (no operator action)"
T1=""; t0=$(date +%s)
while [ $(( $(date +%s) - t0 )) -lt 150 ]; do
  T1="$(poll_endpoint "$TARGET")"; [ -n "$T1" ] && break; sleep 5
done
if [ -n "$T1" ]; then PASS "endpoint $TARGET:443 appeared, last_seen_at T1=$T1"; else FAIL "no endpoint for $TARGET:443 within 150 s"; fi

STEP "T2: a later tick refreshes last_seen_at"
T2=""
if [ -n "$T1" ]; then
  t0=$(date +%s)
  while [ $(( $(date +%s) - t0 )) -lt 150 ]; do
    cur="$(poll_endpoint "$TARGET")"
    if [ -n "$cur" ] && newer "$cur" "$T1"; then T2="$cur"; break; fi
    sleep 5
  done
fi
if [ -n "$T2" ]; then PASS "scheduler refreshed last_scanned unattended: $T1 -> $T2"; else FAIL "last_seen_at never advanced past T1 within 150 s"; fi

STEP "no operator-created scans (acceptance: unattended)"
curlj "${HUB_BASE}/api/v1/audit?action=discovery.scan.create&limit=100" >"$WORK/audit-scan-create.json"
n="$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["data"]))' "$WORK/audit-scan-create.json" 2>/dev/null || echo ERR)"
if [ "$n" = 0 ]; then PASS "0 discovery.scan.create audit entries (script never POSTed a scan)"; else FAIL "audit shows $n discovery.scan.create entries (expected 0)"; fi

STEP "schedule row (W24-04)"
code="$(curlj -o "$WORK/schedule.json" -w '%{http_code}' "${HUB_BASE}/api/v1/discovery/schedules")"
if [ "$code" = 404 ]; then
  echo "SKIP: /discovery/schedules returned 404 (W24-04 not in this build)"
elif [ "$code" = 200 ] && python3 - "$WORK/schedule.json" "$TARGET" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))["data"]
rows = d if isinstance(d, list) else next((v for v in d.values() if isinstance(v, list)), [])
sys.exit(0 if any(r.get("target") == sys.argv[2] and r.get("last_run") for r in rows) else 1)
PY
then PASS "schedule for $TARGET has non-null last_run"
else FAIL "no schedule row for $TARGET with last_run (HTTP $code)"; fi

if [ -n "${KK_EVIDENCE_DIR:-}" ]; then
  mkdir -p "$KK_EVIDENCE_DIR"
  cp "$WORK/schedule.json" "$WORK/audit-scan-create.json" "$KK_EVIDENCE_DIR/" 2>/dev/null || true
fi
STEP "result"
if [ "$FAILED" -eq 0 ]; then echo "ALL PASS"; exit 0; fi
echo "ONE OR MORE STEPS FAILED (hub logs: podman logs $HUB_CTR)"; exit 1
