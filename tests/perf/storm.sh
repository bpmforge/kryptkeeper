#!/usr/bin/env bash
# W30-22: renewal-storm drain benchmark. Makes --certs certificates due at once, drains them through
# POST /api/v1/certificates/{fp}/renew with --agents parallel simulated agents (optionally capped at
# --rate requests per second in total), and reports minutes from the first to the last
# certificate.renew success audit event.
#
#   bash tests/perf/storm.sh [--certs 50000] [--agents 16] [--rate 0] [--out DIR]
#
# Drives the renew API, so it measures CA signing, DB writes and audit append at storm volume. It does
# NOT measure the hub scheduler's serial loop (certificate.renew_execute) or SSH install.
# The pass/fail judgement belongs to the Go test (tests/perf/run_test.go); this script exits 0 once
# storm.json is written, even when requests failed.
# Overrides: PG_IMAGE, CONTAINER_ENGINE (see bench.sh), STORM_STALL_SECS (default 600).
set -euo pipefail

STORM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=bench.sh
source "$STORM_DIR/bench.sh"

STALL_SECS="${STORM_STALL_SECS:-600}"
TOKEN_REFRESH_SECS=480

# Success count of certificate.renew audit events. Total is the unpaged match count.
renew_total() {
  curl -fsS -H "Authorization: Bearer $(cat "$OUT/token")" \
    "$HUB_BASE/api/v1/audit?action=certificate.renew&outcome=success&limit=1" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["meta"]["total"])'
}

renew_edge_ts() { # asc|desc -> RFC3339 timestamp of the first/last success event
  curl -fsS -H "Authorization: Bearer $(cat "$OUT/token")" \
    "$HUB_BASE/api/v1/audit?action=certificate.renew&outcome=success&order=$1&limit=1" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["data"][0]["timestamp"])'
}

# Replace the access token before it expires. One login per refresh keeps far below the 10/min limiter.
token_refresher() {
  while sleep "$TOKEN_REFRESH_SECS"; do
    api_token >"$OUT/token.new" 2>/dev/null && mv "$OUT/token.new" "$OUT/token" || true
  done
}

# One simulated agent request: a fresh P-256 CSR, then the renew call. Prints the HTTP status.
storm_one() {
  local fp="$1" csr body
  csr="$(openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout /dev/null \
    -subj "/CN=storm-${fp:0:12}.perf.example.com" \
    -addext "subjectAltName=DNS:storm-${fp:0:12}.perf.example.com" 2>/dev/null)" || { echo 000; return; }
  body="$(printf '%s' "$csr" | python3 -c 'import json,sys; print(json.dumps({"csr_pem": sys.stdin.read()}))')"
  curl -s -o /dev/null -w '%{http_code}\n' --max-time 300 -X POST \
    -H "Authorization: Bearer $(cat "$OUT/token")" -H 'Content-Type: application/json' \
    -d "$body" "$HUB_BASE/api/v1/certificates/$fp/renew" || echo 000
  if [[ "$RATE" != "0" ]]; then sleep "$(python3 -c 'import sys; print(float(sys.argv[1])/float(sys.argv[2]))' "$AGENTS" "$RATE")"; fi
}

# Clone renewable seed rows until $1 additional rows exist that expire within 30 days.
insert_due_rows() {
  local n="$1" seeds
  seeds="$(psql_exec -c "SELECT count(*) FROM certificates WHERE renewal_status='active' AND successor_fingerprint IS NULL AND revoked_at IS NULL")"
  ((seeds > 0)) || { log "no renewable seed rows to clone"; return 1; }
  psql_exec <<SQL
CREATE EXTENSION IF NOT EXISTS pgcrypto;
DO \$\$
DECLARE cols text;
BEGIN
  SELECT string_agg(quote_ident(column_name), ', ' ORDER BY ordinal_position) INTO cols
    FROM information_schema.columns
   WHERE table_schema = 'public' AND table_name = 'certificates'
     AND is_generated = 'NEVER' AND is_identity = 'NO'
     AND column_name NOT IN ('fingerprint_sha256', 'serial_number', 'created_at', 'valid_until',
                             'renewal_status', 'successor_fingerprint', 'predecessor_fingerprint',
                             'revoked_at', 'revocation_reason');
  EXECUTE format(
    'INSERT INTO certificates (fingerprint_sha256, serial_number, created_at, valid_until, renewal_status, %1\$s)
     SELECT encode(gen_random_bytes(32), ''hex''), encode(gen_random_bytes(16), ''hex''),
            now(), now() + interval ''10 days'', ''active'', %1\$s
       FROM (SELECT * FROM certificates
              WHERE renewal_status = ''active'' AND successor_fingerprint IS NULL AND revoked_at IS NULL
              ORDER BY fingerprint_sha256) src
       CROSS JOIN generate_series(1, $(((n + seeds - 1) / seeds))) g
       LIMIT $n', cols);
END \$\$;
ANALYZE certificates;
SQL
}

main() {
  local certs=50000 AGENTS=16 RATE=0 out=""
  while (($#)); do
    case "$1" in
      --certs) certs="$2"; shift 2 ;;
      --agents) AGENTS="$2"; shift 2 ;;
      --rate) RATE="$2"; shift 2 ;;
      --out) out="$2"; shift 2 ;;
      *) echo "usage: storm.sh [--certs N] [--agents N] [--rate R] [--out DIR]" >&2; exit 64 ;;
    esac
  done
  ((AGENTS >= 1 && AGENTS <= 64)) || { echo "--agents must be 1..64 (ephemeral ports)" >&2; exit 64; }
  [[ -n "$out" ]] || out="$(mktemp -d)"
  mkdir -p "$out"
  OUT="$(cd "$out" && pwd)"
  export OUT AGENTS RATE
  trap 'kill "${REFRESH_PID:-}" 2>/dev/null; perf_down' EXIT

  perf_up 1000
  api_token >"$OUT/token"
  token_refresher &
  REFRESH_PID=$!

  log "making $certs certificates due"
  insert_due_rows "$certs"
  local due
  due="$(psql_exec -c "SELECT count(*) FROM certificates WHERE valid_until < now() + interval '30 days' AND renewal_status='active' AND successor_fingerprint IS NULL AND revoked_at IS NULL")"
  if ((due != certs)); then log "due rows $due != $certs"; return 1; fi
  psql_exec -c "COPY (SELECT fingerprint_sha256 FROM certificates WHERE valid_until < now() + interval '30 days' AND renewal_status='active' AND successor_fingerprint IS NULL AND revoked_at IS NULL) TO STDOUT" >"$OUT/fps.txt"

  # Peak RSS sampler, as in perf_measure.
  local rsslog="$OUT/rss.samples" sampler
  : >"$rsslog"
  (while kill -0 "$HUB_PID" 2>/dev/null; do ps -o rss= -p "$HUB_PID" >>"$rsslog" 2>/dev/null || true; sleep 2; done) &
  sampler=$!

  local base t0
  base="$(renew_total)"
  t0="$(date +%s)"
  log "baseline renew successes $base; $AGENTS agents, rate $RATE/s, $certs certs"
  export -f storm_one
  export HUB_BASE
  : >"$OUT/codes.txt"
  (xargs -P "$AGENTS" -n 1 bash -c 'storm_one "$1"' _ <"$OUT/fps.txt" >"$OUT/codes.txt") &
  local xpid=$!

  local done_n=0 last_n=-1 last_progress="$t0" now
  while true; do
    sleep 15
    done_n="$(renew_total)"
    now="$(date +%s)"
    if ((done_n != last_n)); then last_n="$done_n"; last_progress="$now"; fi
    log "renewed $((done_n - base))/$certs, $((now - t0))s elapsed"
    if ((done_n - base >= certs)); then break; fi
    if ((now - last_progress > STALL_SECS)); then
      log "no progress for ${STALL_SECS}s; partial count $((done_n - base))"
      break
    fi
    if ! kill -0 "$xpid" 2>/dev/null && ((now - last_progress > 60)); then break; fi
  done
  kill "$xpid" 2>/dev/null || true
  pkill -P "$xpid" 2>/dev/null || true
  wait "$xpid" 2>/dev/null || true
  done_n="$(renew_total)"

  sleep 2
  ps -o rss= -p "$HUB_PID" >>"$rsslog" 2>/dev/null || true
  kill "$sampler" 2>/dev/null || true
  wait "$sampler" 2>/dev/null || true

  local first last
  first="$(renew_edge_ts asc)"
  last="$(renew_edge_ts desc)"
  sort "$OUT/codes.txt" | uniq -c | sort -rn >"$OUT/codes.hist"
  python3 - "$OUT" "$certs" "$AGENTS" "$RATE" "$first" "$last" "$((done_n - base))" "$PG_VERSION" \
    "$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)" <<'PY'
import json, sys
from datetime import datetime, timezone
out, certs, agents, rate, first, last, ok, pg, sha = sys.argv[1:]
ts = lambda s: datetime.fromisoformat(s.replace("Z", "+00:00"))
minutes = round((ts(last) - ts(first)).total_seconds() / 60, 2)
codes = [l.strip() for l in open(out + "/codes.txt") if l.strip()]
hist = {}
for c in codes:
    hist[c] = hist.get(c, 0) + 1
rss = [int(x) for x in open(out + "/rss.samples").read().split()]
certs, ok = int(certs), int(ok)
res = {
    "suite": "storm",
    "certs": certs, "agents": int(agents), "rate_per_sec": float(rate),
    "success": ok, "failures": certs - ok, "drained": ok == certs,
    "storm_drain_minutes": minutes,
    "first_event": first, "last_event": last,
    "http_codes": hist,
    "rss_mib_peak": round(max(rss) / 1024, 1) if rss else 0,
    "postgres": pg, "git_sha": sha,
    "date": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
}
# The scaled nightly run is judged under its own key (bar 6 min at 5,000 certs).
if certs == 5000:
    res["storm_drain_minutes_5k"] = minutes
json.dump(res, open(out + "/storm.json", "w"), indent=1)
PY
  log "wrote $OUT/storm.json"
  cat "$OUT/storm.json"
}

main "$@"
