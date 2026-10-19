#!/usr/bin/env bash
# W27-34: 2,000-certificate renewal storm against a rate-limited stub CA.
#
#   bash run.sh [full|smoke]
#
# A real hub container's real scheduler renews N due certificates through an
# ACME connector pointed at a stub CA that allows LIMIT new orders per 15 min of
# simulated time, installs each into a fake Kubernetes Secrets API and verifies
# it by TLS-dialling a per-target listener. All wall-clock quantities are
# divided by SCALE (see README.md). Writes results/<UTC stamp>.json, prints a
# markdown summary, exits 1 when a measured criterion fails, 2 when it cannot
# run (no podman). Legs that did not run are null, never pass.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib/podman.sh"
set -u
set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
MODE="${1:-full}"

# --- scenario constants (edit here, and the change is recorded in results) ---
case "$MODE" in
  full)  N=2000; SCALE=60;  LIMIT=100; IMPORT_ALLOW_S=150 ;;
  # The poll cadence floor is 1 minute (RENEWAL_POLL_MINUTES), so a scale
  # above ~100 makes 7h/SCALE shorter than one tick and every cert expires
  # unrenewed; smoke therefore uses 120, and a limit of N/5 so the stub CA
  # still refuses orders.
  smoke) N=100;  SCALE=120; LIMIT=20;  IMPORT_ALLOW_S=15 ;;
  *) echo "usage: run.sh [full|smoke]"; exit 2 ;;
esac
SCALE="${KK_STORM_SCALE:-$SCALE}"
N="${KK_STORM_N:-$N}"
LIMIT="${KK_STORM_LIMIT:-$LIMIT}"
# Certificates are imported before the storm starts (bindings last), so their
# lifetime is allowance + EXPIRY_S; the real time left at the storm's start is
# measured and is what the before-expiry check uses.
IMPORT_ALLOW_S="${KK_STORM_IMPORT_ALLOW:-$IMPORT_ALLOW_S}"
CAP=10                 # KRYPTKEEPER_CONNECTOR_MAX_CONCURRENT
WORKERS=16             # KRYPTKEEPER_RENEWAL_WORKERS
JITTER_PERCENT=10      # RENEWAL_TICK_JITTER_PERCENT
POLL_MINUTES=1         # RENEWAL_POLL_MINUTES
# Simulated: 100 orders / 15 min, 3 s per order, certs expire 7 h after
# seeding, goal 6 h. Real = simulated / SCALE.
WINDOW_MS="$(python3 -c "print(int(900000/$SCALE))")"
SERVICE_MS="$(python3 -c "print(int(3000/$SCALE))")"
EXPIRY_S="$(python3 -c "print(int(25200/$SCALE))")"
MIN_BACKOFF_MS="$(python3 -c "print(max(1,int(30000/$SCALE)))")"   # the throttle's 30 s 429-backoff floor, scaled like everything else
ACME_JITTER_MS="$(python3 -c "print(max(1,int(60000/$SCALE)))")"   # W26-28's 0-60 s Retry-After jitter, scaled likewise
GOAL_S="$(python3 -c "print(int(21600/$SCALE))")"
POLL_SLACK_S=300
VERIFY_BASE=21000
TOKEN="storm-bootstrap-token"

command -v podman >/dev/null 2>&1 || { echo "SKIP: podman not installed"; exit 2; }
for c in go python3 curl; do command -v "$c" >/dev/null 2>&1 || { echo "SKIP: $c not installed"; exit 2; }; done
podman info >/dev/null 2>&1 || { echo "SKIP: podman is not usable (is the machine running?)"; exit 2; }

RUN_ID="$(openssl rand -hex 3)"
WORK="$(mktemp -d /tmp/kk-storm.XXXXXX)"
STAMP="$(date -u +%Y-%m-%dT%H%M%SZ)"
mkdir -p "$HERE/results"
HUB_IMAGE="localhost/kk-storm-hub:$RUN_ID"
FIX_IMAGE="localhost/kk-storm-fixture:$RUN_ID"
CREATED=()   # containers, networks and volumes to remove at exit
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()'; }
STEP() { echo; echo "=== $* ==="; }
DIE()  { echo "FAIL: $*"; exit 1; }
cleanup() {
  for r in "${CREATED[@]:-}"; do
    case "$r" in
      c:*) kk_rm "${r#c:}" ;;
      n:*) podman network rm "${r#n:}" >/dev/null 2>&1 ;;
      v:*) podman volume rm -f "${r#v:}" >/dev/null 2>&1 ;;
    esac
  done
  podman rmi -f "$HUB_IMAGE" "$FIX_IMAGE" >/dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT

STEP "build hub and fixture images ($MODE: N=$N scale=$SCALE limit=$LIMIT/${WINDOW_MS}ms cap=$CAP)"
GOARCH="$(kk_goarch)"
mkdir -p "$WORK/hubctx" "$WORK/fixctx"
(cd "$REPO_ROOT" && GOOS=linux GOARCH=$GOARCH CGO_ENABLED=0 go build -o "$WORK/hubctx/kryptkeeper" ./cmd/kryptkeeper) || DIE "hub build failed"
(cd "$REPO_ROOT" && GOOS=linux GOARCH=$GOARCH CGO_ENABLED=0 go build -o "$WORK/fixctx/fixture" ./tests/live/storm/fixture) || DIE "fixture build failed"
(cd "$REPO_ROOT" && go build -o "$WORK/fixture-host" ./tests/live/storm/fixture) || DIE "host fixture build failed"
cp "$REPO_ROOT/tests/live/autopilot/hub.Containerfile" "$WORK/hubctx/Containerfile"
cp "$HERE/fixture.Containerfile" "$WORK/fixctx/Containerfile"
podman build -q -t "$HUB_IMAGE" "$WORK/hubctx" >"$WORK/build-hub.log" 2>&1 || DIE "hub image: $(tail -5 "$WORK/build-hub.log")"
podman build -q -t "$FIX_IMAGE" "$WORK/fixctx" >"$WORK/build-fix.log" 2>&1 || DIE "fixture image: $(tail -5 "$WORK/build-fix.log")"
COMMIT="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"

# stat_get FIELD  -> value from the fixture's /stats ("" when unreachable)
stat_get() {
  curl -sk -m 5 "https://127.0.0.1:$STATS_PORT/stats" 2>/dev/null | python3 -c "import json,sys
try: print(json.load(sys.stdin)['$1'])
except Exception: print('')" 2>/dev/null
}
hub_healthy() { curl -sf -m 3 "http://127.0.0.1:$HUB_PORT/healthz" >/dev/null 2>&1; }
wait_hub() { for _ in $(seq 1 90); do hub_healthy && return 0; sleep 1; done; return 1; }

# run_leg LABEL RESTART_MODE(none|stop|kill)
# Fills $WORK/leg-LABEL.json with stats, timings and audit counts.
run_leg() {
  local label="$1" restart="$2"
  local net="kk-storm-net-$RUN_ID-$label" outvol="kk-storm-out-$RUN_ID-$label" datavol="kk-storm-data-$RUN_ID-$label"
  local fix="kk-storm-fixture-$RUN_ID-$label" hub="kk-storm-hub-$RUN_ID-$label"
  HUB_PORT="$(free_port)"; STATS_PORT="$(free_port)"
  STEP "leg $label (restart: $restart)"
  podman network create "$net" >/dev/null || DIE "network create"; CREATED+=("n:$net")
  podman volume create "$outvol" >/dev/null; podman volume create "$datavol" >/dev/null; CREATED+=("v:$outvol" "v:$datavol")
  podman run -d --name "$fix" --network "$net" --network-alias fixture -v "$outvol:/out" -p "127.0.0.1:$STATS_PORT:9443" \
    "$FIX_IMAGE" serve --limit "$LIMIT" --window "${WINDOW_MS}ms" --service "${SERVICE_MS}ms" --grace 1s \
    --verify-base "$VERIFY_BASE" --verify-count "$N" >/dev/null || DIE "fixture did not start"
  CREATED+=("c:$fix")
  for _ in $(seq 1 60); do [ -n "$(stat_get orders)" ] && break; sleep 1; done
  [ -n "$(stat_get orders)" ] || { podman logs "$fix" 2>&1 | tail; DIE "fixture stats unreachable"; }
  podman cp "$fix:/out/ca.pem" "$WORK/ca-$label.pem" || DIE "no ca.pem from fixture"

  cat >"$WORK/hub.env" <<ENV
APP_BOOTSTRAP_TOKEN=$TOKEN
AUTH_MODE=bootstrap
APP_CERTIFICATE_PROVIDER=ca
APP_API_KEY_PEPPER=storm-pepper-32-characters-minimum!!
APP_API_KEY_AUTH_ENABLED=true
APP_CREDENTIAL_STORE_PASSPHRASE=storm-cred-passphrase-32-bytes-long!
KRYPTKEEPER_KEYSTORE_PASSPHRASE=storm-keystore-passphrase-32-bytes!
KRYPTKEEPER_DATA_DIR=/data
APP_CA_FILE=/data/cas.json
APP_TEMPLATE_FILE=/data/templates.json
APP_CERTIFICATE_FILE=/data/certificates.json
APP_AUDIT_FILE=/data/audit.json
APP_CERTS_SUMMARY_FILE=/data/certs_summary.json
KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true
KRYPTKEEPER_CA_NAME=Storm Root CA
APP_BIND_ADDR=0.0.0.0
PORT=$HUB_PORT
KRYPTKEEPER_TLS_DISABLE=true
RENEWAL_POLL_MINUTES=$POLL_MINUTES
KRYPTKEEPER_CONNECTOR_MAX_CONCURRENT=$CAP
KRYPTKEEPER_RENEWAL_WORKERS=$WORKERS
RENEWAL_TICK_JITTER_PERCENT=$JITTER_PERCENT
KRYPTKEEPER_CONNECTOR_MIN_BACKOFF=${MIN_BACKOFF_MS}ms
KRYPTKEEPER_ACME_RATELIMIT_JITTER_MAX=${ACME_JITTER_MS}ms
SSL_CERT_FILE=/fixture/ca.pem
ENV
  # A published port can be taken between free_port and the bind; retry on a new one.
  local tries=0
  until podman run -d --name "$hub" --network "$net" -p "127.0.0.1:$HUB_PORT:$HUB_PORT" -v "$datavol:/data" -v "$outvol:/fixture:ro" \
      --env-file "$WORK/hub.env" "$HUB_IMAGE" >/dev/null 2>&1; do
    tries=$((tries + 1)); [ "$tries" -ge 5 ] && DIE "hub did not start"
    kk_rm "$hub"
    HUB_PORT="$(free_port)"; sed -i.bak "s/^PORT=.*/PORT=$HUB_PORT/" "$WORK/hub.env"
  done
  CREATED+=("c:$hub")
  wait_hub || { podman logs "$hub" 2>&1 | tail -20; DIE "hub did not become healthy"; }

  # The scheduler's one-time CN/SAN backfill runs on its first tick; let it
  # finish on the empty hub so it cannot bind a half-seeded estate.
  for _ in $(seq 1 60); do
    curl -s -m 3 -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$HUB_PORT/api/v1/scheduler/renewal/status" 2>/dev/null | grep -q '"has_run":true' && break
    sleep 1
  done

  local t_seed0 t0
  t_seed0=$(date +%s)
  echo "seeding $N certificates (time left at storm start: ~${EXPIRY_S}s)"
  KK_TOKEN="$TOKEN" "$WORK/fixture-host" seed --hub "http://127.0.0.1:$HUB_PORT" --count "$N" \
    --expiry "${EXPIRY_S}s" --import-allowance "${IMPORT_ALLOW_S}s" \
    --ca-pem "$WORK/ca-$label.pem" --verify-base "$VERIFY_BASE" >"$WORK/seed-$label.json" 2>"$WORK/seed-$label.err" \
    || { tail -5 "$WORK/seed-$label.err"; DIE "seeding failed"; }
  t0=$(python3 -c "import json;print(json.load(open('$WORK/seed-$label.json'))['t0_unix'])")
  echo "seeded in $(( $(date +%s) - t_seed0 ))s: $(cat "$WORK/seed-$label.json")"

  local deadline=$((t0 + GOAL_S + POLL_SLACK_S)) restarted=0 restart_at_s="" done_at="" fin=0 max_inflight=0 samples=0
  : >"$WORK/series-$label.csv"
  while :; do
    local now fin_s; now=$(date +%s)
    fin_s="$(stat_get finalized_unique)"; fin="${fin_s:-0}"
    printf '%s,%s,%s,%s,%s\n' "$((now - t0))" "$fin" "$(stat_get orders)" "$(stat_get limit_hits)" "$(stat_get violations)" >>"$WORK/series-$label.csv"
    # The hub's own view of its connector budgets (in_flight vs cap).
    local inf
    inf="$(curl -s -m 5 -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$HUB_PORT/api/v1/reports/renewal-slo" 2>/dev/null | python3 -c "import json,sys
try: print(max([b['in_flight'] for b in json.load(sys.stdin)['data']['queue']['connector_budgets']] or [0]))
except Exception: print(0)" 2>/dev/null)"
    [ "${inf:-0}" -gt "$max_inflight" ] 2>/dev/null && max_inflight="$inf"
    samples=$((samples + 1))
    if [ "$restarted" = 0 ] && [ "$restart" != none ] && [ "$fin" -ge $((N / 2)) ]; then
      restart_at_s=$((now - t0))
      echo "restart ($restart) at +${restart_at_s}s with $fin/$N finalized"
      if [ "$restart" = stop ]; then podman stop "$hub" >/dev/null 2>&1; else podman kill "$hub" >/dev/null 2>&1; fi
      podman start "$hub" >/dev/null 2>&1
      wait_hub || echo "hub did not come back after restart"
      restarted=1
    fi
    [ "$fin" -ge "$N" ] && { done_at=$(date +%s); break; }
    [ "$now" -ge "$deadline" ] && break
    sleep 5
  done
  local completion=""; [ -n "$done_at" ] && completion=$((done_at - t0))
  echo "leg $label: finalized_unique=$fin/$N completion_s=${completion:-none}"

  # Settle: the install leg and audit rows trail the last finalize.
  sleep 20
  python3 - "$HUB_PORT" "$TOKEN" "$WORK/audit-$label.json" <<'PY'
import json, sys, urllib.request
port, token, out = sys.argv[1:4]
def pull(qs):
    rows, cursor = [], ""
    while True:
        url = f"http://127.0.0.1:{port}/api/v1/audit?limit=100&{qs}" + (f"&cursor={cursor}" if cursor else "")
        d = json.load(urllib.request.urlopen(urllib.request.Request(url, headers={"Authorization": "Bearer " + token}), timeout=60))
        rows += d["data"]
        cursor = (d.get("meta") or {}).get("next_cursor") or ""
        if not cursor:
            return rows
ok = pull("action=certificate.renew_execute&outcome=success")
fail = pull("action=certificate.renew_execute_failed") + pull("action=certificate.renew_execute_partial")
deferred = pull("action=certificate.renew_execute_deferred")
limited = pull("action=connector.rate_limited")
acme_limited = pull("action=acme.upstream.ratelimited")  # W26-28 gate deferrals
json.dump({"success_unique": len({r["resource_id"] for r in ok}), "success_rows": len(ok),
           "failed_rows": len(fail), "deferred_rows": len(deferred), "rate_limited_rows": len(limited), "acme_ratelimited_rows": len(acme_limited)}, open(out, "w"))
PY
  podman logs "$hub" >"$WORK/hub-$label.log" 2>&1
  [ -n "${KK_STORM_LOGDIR:-}" ] && { mkdir -p "$KK_STORM_LOGDIR"; cp "$WORK/hub-$label.log" "$KK_STORM_LOGDIR/hub-$label.log"; podman logs "$fix" >"$KK_STORM_LOGDIR/fixture-$label.log" 2>&1; }
  python3 - "$label" "$WORK" "${completion:-}" "$t0" "$t_seed0" "${restart_at_s:-}" "$max_inflight" "$samples" "$(stat_get orders)" <<'PY'
import json, sys
label, work, completion, t0, tseed0, restart_at, max_inflight, samples, _ = sys.argv[1:10]
st = {}
import subprocess
leg = {
    "label": label,
    "completion_s": int(completion) if completion else None,
    "restart_at_s": int(restart_at) if restart_at else None,
    "hub_max_in_flight_sampled": int(max_inflight),
    "samples": int(samples),
    "audit": json.load(open(f"{work}/audit-{label}.json")),
    "seed": json.load(open(f"{work}/seed-{label}.json")),
}
json.dump(leg, open(f"{work}/leg-{label}.json", "w"))
PY
  curl -sk -m 5 "https://127.0.0.1:$STATS_PORT/stats" >"$WORK/stats-$label.json"
  echo "stats: $(cat "$WORK/stats-$label.json")"
  kk_rm "$hub" "$fix"
  podman network rm "$net" >/dev/null 2>&1
}

run_leg A none
run_leg B stop
if [ "$MODE" = full ]; then run_leg B2 kill; fi

STEP "results"
OUT="$HERE/results/$STAMP.json"
CPU="$(sysctl -n machdep.cpu.brand_string 2>/dev/null || grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs)"
CORES="$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null)"
RAMGB="$(python3 -c "import subprocess,sys
try: print(round(int(subprocess.check_output(['sysctl','-n','hw.memsize']))/2**30))
except Exception:
    print(round(int(open('/proc/meminfo').readline().split()[1])/2**20))")"
python3 - "$WORK" "$OUT" "$MODE" "$N" "$SCALE" "$LIMIT" "$CAP" "$WINDOW_MS" "$SERVICE_MS" "$EXPIRY_S" "$GOAL_S" "$WORKERS" "$POLL_MINUTES" "$JITTER_PERCENT" "$CPU" "$CORES" "$RAMGB" "$(go version | awk '{print $3}')" "$COMMIT" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$IMPORT_ALLOW_S" <<'PY'
import json, os, sys
(work, out, mode, n, scale, limit, cap, window_ms, service_ms, expiry_s, goal_s, workers, poll, jitter,
 cpu, cores, ram, gover, commit, utc, import_allow) = sys.argv[1:22]
n, cap, expiry_s, goal_s = int(n), int(cap), int(expiry_s), int(goal_s)
def leg(l):
    p = f"{work}/leg-{l}.json"
    if not os.path.exists(p):
        return None, None
    return json.load(open(p)), json.load(open(f"{work}/stats-{l}.json"))
a, sa = leg("A"); b, sb = leg("B"); b2, sb2 = leg("B2")

def ok_run(l, s):
    """Every acceptance criterion for one run; None when the run did not happen."""
    if l is None:
        return None
    c = l["completion_s"]
    return {
        "all_finalized": s["finalized_unique"] == n,
        "completion_within_goal": c is not None and c <= goal_s,
        "before_earliest_expiry": c is not None and c < l["seed"]["remaining_s"],
        "zero_ca_limit_violations": s["violations"] == 0,
        "zero_late_violations": s["late_violations"] == 0,
        "peak_in_flight_within_cap": s["peak_in_flight"] <= cap and l["hub_max_in_flight_sampled"] <= cap,
        "zero_duplicate_issuance": s["duplicates"] == 0,
        "all_have_successor": l["audit"]["success_unique"] == n,
    }
pa, pb, pb2 = ok_run(a, sa), ok_run(b, sb), ok_run(b2, sb2)
res = {
    "mode": mode, "scale": int(scale), "n": n, "limit": f"{limit} new orders per {window_ms} ms (real)", "cap": cap,
    "constants": {"workers": int(workers), "poll_minutes": int(poll), "jitter_percent": int(jitter),
                  "stub_service_ms": int(service_ms), "expiry_s": expiry_s, "import_allowance_s": int(import_allow), "goal_s": goal_s},
    "completion_s_run_a": a and a["completion_s"], "completion_s_run_b": b and b["completion_s"],
    "completion_s_run_b2": b2 and b2["completion_s"],
    "stats_a": sa, "stats_b": sb, "stats_b2": sb2,
    "legs": {"a": a, "b": b, "b2": b2},
    "restarts": {"b": b and {"mode": "stop", "at_s": b["restart_at_s"]}, "b2": b2 and {"mode": "kill", "at_s": b2["restart_at_s"]}},
    "env": {"cpu": cpu, "cores": cores, "ram_gb": ram, "go": gover, "commit": commit, "utc": utc},
    "pass": {"run_a": pa, "run_b": pb, "run_b2_informational": pb2},
}
json.dump(res, open(out, "w"), indent=2)
print(f"\n{cpu} / {cores} cores / {ram} GB / {gover} / {commit} / {utc}")
print(f"\nmode={mode} N={n} scale={scale} limit={limit}/{window_ms}ms cap={cap} goal={goal_s}s expiry={expiry_s}s\n")
print("| run | completion s | finalized | orders | 429s | violations (strict) | late violations | peak in flight | duplicates | success audits |")
print("|---|---|---|---|---|---|---|---|---|---|")
for name, l, s in (("A uninterrupted", a, sa), ("B graceful restart", b, sb), ("B2 kill -9 (info)", b2, sb2)):
    if l is None:
        print(f"| {name} | NOT RUN | | | | | | | | |")
        continue
    print(f"| {name} | {l['completion_s']} | {s['finalized_unique']} | {s['orders']} | {s['limit_hits']} | {s['violations']} | {s['late_violations']} | {s['peak_in_flight']} | {s['duplicates']} | {l['audit']['success_unique']} |")
print("\npass:", json.dumps(res["pass"], indent=1))
fails = [k for k in ("run_a", "run_b") if res["pass"][k] and any(v is False for v in res["pass"][k].values())]
sys.exit(1 if fails else 0)
PY
RC=$?
# Stamped results are git-ignored run output; last-run.json is the one tracked record.
cp "$OUT" "$HERE/results/last-run.json"
echo "results: $OUT"
exit "$RC"
