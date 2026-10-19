#!/usr/bin/env bash
# W30-21: Postgres scale benchmark. One script seeds N certificates into Postgres 16, measures
# search p99, list p95, issuance rate at c=16 and peak hub RSS, and writes results.json.
# The pass/fail judgement belongs to the Go test (tests/perf/run_test.go), so a 1M run never
# fails this script.
#
#   bash tests/perf/bench.sh [--certs N] [--no-bar] [--out DIR]
#
# Functions are source-able: tests/perf/storm.sh (W30-22) reuses perf_up / perf_down.
# Overrides: PG_IMAGE (default pins the 16.15 minor), CONTAINER_ENGINE (default podman).
set -euo pipefail

PERF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$PERF_DIR/../.." && pwd)"
PG_IMAGE="${PG_IMAGE:-docker.io/library/postgres:16.15}"
ENGINE="${CONTAINER_ENGINE:-podman}"
LOADTOOL_SRC="$REPO_ROOT/docs/perf/rc1/harness/loadtool.go.txt"
SEED_ROWS=500

log() { printf '[perf %s] %s\n' "$(date '+%H:%M:%S')" "$*" >&2; }
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }

psql_exec() { "$ENGINE" exec -i "$PG_CONTAINER" psql -U kryptkeeper -d kryptkeeper -v ON_ERROR_STOP=1 -tA "$@"; }

wait_http() { # url, tries
  local i
  for ((i = 0; i < ${2:-120}; i++)); do
    curl -fsS -o /dev/null "$1" 2>/dev/null && return 0
    sleep 1
  done
  return 1
}

start_hub() {
  # Repo-relative equivalent of docs/perf/rc1/harness/start-hub.sh.txt; Postgres instead of SQLite.
  APP_TRUSTED_PROXY_CIDRS=127.0.0.0/8 APP_AUDIT_PROVIDER=db APP_CERTIFICATE_PROVIDER=ca \
    KRYPTKEEPER_TLS_DISABLE=true KRYPTKEEPER_DATA_DIR="$WORK/data" \
    KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true KRYPTKEEPER_CA_NAME="Perf Root CA" \
    KRYPTKEEPER_KEYSTORE_PASSPHRASE="$KS" APP_BOOTSTRAP_TOKEN="$BOOT" \
    APP_AUTH_LOGIN_ENABLED=true APP_AUTH_LOGIN_EMAIL=perf@example.com \
    APP_AUTH_LOGIN_PASSWORD_PEPPER="$PEPPER" APP_AUTH_LOGIN_PASSWORD_HASH="$HASH" \
    APP_AUTH_LOGIN_SUBJECT=perf APP_AUTH_LOGIN_ROLE=pki-admin APP_AUTH_LOGIN_ACTIVE=true \
    APP_AUTH_LOGIN_SIGNING_SECRET="$SIGN" RENEWAL_POLL_MINUTES=1 \
    APP_TEMPLATE_FILE="$WORK/templates.json" \
    KRYPTKEEPER_DB_MODE=postgres DATABASE_URL="$PG_DSN" PORT="$HUB_PORT" APP_BIND_ADDR=127.0.0.1 \
    nohup "$WORK/kryptkeeper" >>"$WORK/hub.log" 2>&1 &
  HUB_PID=$!
  export HUB_PID
  if ! wait_http "$HUB_BASE/readyz" 180; then
    log "hub did not become ready; tail of hub.log:"
    tail -n 20 "$WORK/hub.log" >&2 || true
    return 1
  fi
}

stop_hub() {
  if [[ -n "${HUB_PID:-}" ]] && kill -0 "$HUB_PID" 2>/dev/null; then
    kill "$HUB_PID" 2>/dev/null || true
    wait "$HUB_PID" 2>/dev/null || true
  fi
}

build_loadtool() {
  mkdir -p "$WORK/loadtool"
  cp "$LOADTOOL_SRC" "$WORK/loadtool/main.go"
  (
    cd "$WORK/loadtool"
    python3 - <<'PY'
import re
p = "main.go"
s = open(p).read()
# p99 column on the bench line
s = s.replace("p95=%s max=%s rps=%.1f", "p95=%s p99=%s max=%s rps=%.1f", 1)
s = s.replace("pct(lat, .95).Round(time.Microsecond), pct(lat, 1).Round(time.Microsecond), float64(*n)/tot.Seconds())",
              "pct(lat, .95).Round(time.Microsecond), pct(lat, .99).Round(time.Microsecond), pct(lat, 1).Round(time.Microsecond), float64(*n)/tot.Seconds())", 1)
# hub address from env (the copied tool hardcodes :8080)
s = s.replace('var base = "http://127.0.0.1:8080"',
              'var base = func() string { if v := os.Getenv("HUB_BASE"); v != "" { return v }; return "http://127.0.0.1:8080" }()', 1)
# keep-alive pool sized to the concurrency; the default 2 idle conns/host exhausts ephemeral ports (RC3 harness caveat)
s = s.replace("var client = &http.Client{Timeout: 300 * time.Second}",
              "var client = &http.Client{Timeout: 300 * time.Second, Transport: &http.Transport{MaxIdleConns: 256, MaxIdleConnsPerHost: 256, IdleConnTimeout: 90 * time.Second}}", 1)
open(p, "w").write(s)
PY
    grep -q 'p99=' main.go || { echo "loadtool patch: p99 not applied" >&2; exit 2; }
    grep -q 'pct(lat, .99)' main.go || { echo "loadtool patch: p99 arg not applied" >&2; exit 2; }
    grep -q 'HUB_BASE' main.go || { echo "loadtool patch: HUB_BASE not applied" >&2; exit 2; }
    grep -q 'MaxIdleConnsPerHost' main.go || { echo "loadtool patch: transport not applied" >&2; exit 2; }
    go mod init loadtool >/dev/null 2>&1
    CGO_ENABLED=0 go build -o loadtool .
  )
}

lt() { HUB_BASE="$HUB_BASE" KKPW="$KKPW" "$WORK/loadtool/loadtool" "$@"; }

api_token() {
  curl -fsS -X POST "$HUB_BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "{\"email\":\"perf@example.com\",\"password\":\"$KKPW\"}" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["access_token"])'
}

first_id() { # path -> id of the first item of data / data.items
  curl -fsS -H "Authorization: Bearer $(api_token)" "$HUB_BASE$1" | python3 -c '
import json, sys
d = json.load(sys.stdin).get("data")
if isinstance(d, dict):
    d = d.get("items", [])
print(d[0]["id"])'
}

# Clone the seed rows inside Postgres until the table holds about N rows. Every column is copied
# from the seed rows except the two unique keys and created_at, which are regenerated.
clone_certificates() {
  local n="$1" have reps
  have="$(psql_exec -c 'SELECT count(*) FROM certificates')"
  if ((have >= n)); then return 0; fi
  reps=$(((n - have + have - 1) / have))
  psql_exec <<SQL
CREATE EXTENSION IF NOT EXISTS pgcrypto;
DO \$\$
DECLARE cols text;
BEGIN
  SELECT string_agg(quote_ident(column_name), ', ' ORDER BY ordinal_position) INTO cols
    FROM information_schema.columns
   WHERE table_schema = 'public' AND table_name = 'certificates'
     AND is_generated = 'NEVER' AND is_identity = 'NO'
     AND column_name NOT IN ('fingerprint_sha256', 'serial_number', 'created_at');
  EXECUTE format(
    'INSERT INTO certificates (fingerprint_sha256, serial_number, created_at, %1\$s)
     SELECT encode(gen_random_bytes(32), ''hex''), encode(gen_random_bytes(16), ''hex''),
            (now() - random() * interval ''730 days'')::%2\$s, %1\$s
       FROM certificates, generate_series(1, $reps)', cols,
    (SELECT data_type FROM information_schema.columns
      WHERE table_name = 'certificates' AND column_name = 'created_at'));
END \$\$;
ANALYZE certificates;
SQL
}

perf_up() {
  local n="${1:-100000}"
  WORK="$(mktemp -d "${TMPDIR:-/tmp}/kk-perf.XXXXXX")"
  RUN_ID="$$-$RANDOM"
  PG_CONTAINER="kk-perf-pg-$RUN_ID"
  PG_VOLUME="kk-perf-pgdata-$RUN_ID"
  PEPPER="$(openssl rand -hex 24)"
  KS="$(openssl rand -hex 24)"
  SIGN="$(openssl rand -hex 32)"
  BOOT="$(openssl rand -hex 16)"
  KKPW="$(openssl rand -hex 12)Aa1!"
  HASH="$(python3 -c 'import hmac,hashlib,sys;print(hmac.new(sys.argv[1].encode(),sys.argv[2].encode(),hashlib.sha256).hexdigest())' "$PEPPER" "$KKPW")"
  local pgpw pgport
  pgpw="$(openssl rand -hex 16)"
  pgport="$(free_port)"
  HUB_PORT="$(free_port)"
  HUB_BASE="http://127.0.0.1:$HUB_PORT"
  PG_DSN="postgres://kryptkeeper:${pgpw}@127.0.0.1:${pgport}/kryptkeeper?sslmode=disable"
  HUB_PID=""
  export WORK RUN_ID PG_CONTAINER PG_VOLUME PEPPER KS SIGN BOOT KKPW HASH HUB_PORT HUB_BASE PG_DSN HUB_PID
  mkdir -p "$WORK/data"

  log "1/4 postgres $PG_IMAGE on 127.0.0.1:$pgport"
  "$ENGINE" volume create "$PG_VOLUME" >/dev/null
  "$ENGINE" run -d --name "$PG_CONTAINER" -v "$PG_VOLUME:/var/lib/postgresql/data" \
    -e POSTGRES_USER=kryptkeeper -e POSTGRES_PASSWORD="$pgpw" -e POSTGRES_DB=kryptkeeper \
    -p "127.0.0.1:$pgport:5432" "$PG_IMAGE" \
    postgres -c shared_buffers=1GB -c max_connections=200 >/dev/null
  local i
  for ((i = 0; i < 90; i++)); do
    "$ENGINE" exec "$PG_CONTAINER" pg_isready -U kryptkeeper -d kryptkeeper -h 127.0.0.1 >/dev/null 2>&1 && break
    sleep 1
  done
  ((i < 90)) || { log "postgres never became ready"; return 1; }
  PG_VERSION="$(psql_exec -c 'SHOW server_version')"
  export PG_VERSION

  log "2/4 build and start hub on $HUB_BASE"
  (cd "$REPO_ROOT" && CGO_ENABLED=0 go build -o "$WORK/kryptkeeper" ./cmd/kryptkeeper)
  # Templates have only a file provider, so the issue path needs one seeded before first start.
  cat >"$WORK/templates.json" <<'JSON'
[{"id":"perf-tls","name":"perf-tls","display_name":"Perf TLS","key_usage":["digitalSignature"],"extended_key_usage":["serverAuth"],"allowed_algorithms":["ECDSA","RSA"],"validity_period":"90d","auto_enroll":false,"active":true,"revision":1,"schema_version":1,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}]
JSON
  start_hub

  log "3/4 build load tool"
  build_loadtool
  CA_ID="$(first_id /api/v1/cas)"
  TPL_ID="$(first_id /api/v1/templates)"
  export CA_ID TPL_ID

  log "4/4 seed $SEED_ROWS real certificates, clone to ~$n"
  lt -mode seed -n "$SEED_ROWS" -c 8 -ca "$CA_ID" -tpl "$TPL_ID" >&2
  clone_certificates "$n"
  local total
  total="$(psql_exec -c 'SELECT count(*) FROM certificates')"
  if ((total < n - SEED_ROWS || total > n + SEED_ROWS)); then
    log "row count $total is outside $n +/- $SEED_ROWS"
    return 1
  fi
  CERT_COUNT="$total"
  export CERT_COUNT
  log "table holds $total certificates; restarting hub for cold caches"
  stop_hub
  start_hub
}

# Pull one field from a loadtool bench line and print it as a plain number (durations in ms).
bench_field() { # field <<< line
  python3 -c '
import re, sys
line, field = sys.stdin.read(), sys.argv[1]
m = re.search(r"\b" + field + r"=(\S+)", line)
if not m:
    sys.exit("field %s missing in: %s" % (field, line))
v = m.group(1)
if field == "rps":
    print(float(v))
else:
    u = re.match(r"([\d.]+)(ns|µs|us|ms|s)$", v)
    f = {"ns": 1e-6, "us": 1e-3, "µs": 1e-3, "ms": 1.0, "s": 1000.0}[u.group(2)]
    print(round(float(u.group(1)) * f, 3))' "$1"
}

bench_failures() { # <<< line ; non-2xx and transport errors (code 0)
  python3 -c '
import re, sys
m = re.search(r"codes=map\[([^\]]*)\]", sys.stdin.read())
bad = 0
for pair in (m.group(1).split() if m else []):
    code, cnt = pair.split(":")
    if not code.startswith("2"):
        bad += int(cnt)
print(bad)'
}

perf_measure() {
  local cn="host-7.perf.example.com" line
  local search_p99 list_p95 issue_rps issue_fail rss rsslog sampler
  rsslog="$WORK/rss.samples"
  : >"$rsslog"
  (while kill -0 "$HUB_PID" 2>/dev/null; do ps -o rss= -p "$HUB_PID" >>"$rsslog" 2>/dev/null || true; sleep 2; done) &
  sampler=$!

  log "search p99 (q=$cn)"
  lt -path "/api/v1/search?q=$cn" -n 200 -c 8 >/dev/null
  line="$(lt -path "/api/v1/search?q=$cn" -n 3000 -c 8)"
  log "$line"
  search_p99="$(bench_field p99 <<<"$line")"

  log "list p95"
  lt -path '/api/v1/certificates?limit=25' -n 200 -c 8 >/dev/null
  line="$(lt -path '/api/v1/certificates?limit=25' -n 3000 -c 8)"
  log "$line"
  list_p95="$(bench_field p95 <<<"$line")"

  log "issuance at c=16"
  lt -issue -method POST -path /api/v1/certificates -ca "$CA_ID" -tpl "$TPL_ID" -n 200 -c 16 >/dev/null
  line="$(lt -issue -method POST -path /api/v1/certificates -ca "$CA_ID" -tpl "$TPL_ID" -n 5000 -c 16)"
  log "$line"
  issue_rps="$(bench_field rps <<<"$line")"
  issue_fail="$(bench_failures <<<"$line")"

  sleep 2
  ps -o rss= -p "$HUB_PID" >>"$rsslog" 2>/dev/null || true
  kill "$sampler" 2>/dev/null || true
  wait "$sampler" 2>/dev/null || true
  rss="$(python3 -c 'import sys; v=[int(x) for x in open(sys.argv[1]).read().split()]; print(round(max(v)/1024, 1))' "$rsslog")"

  RESULTS_JSON="$(python3 -c '
import json, sys
a = sys.argv
print(json.dumps({"certs": int(a[1]), "search_p99_ms": float(a[2]), "list_p95_ms": float(a[3]),
  "issue_rps_c16": float(a[4]), "issue_failures": int(a[5]), "rss_mib_peak": float(a[6]),
  "postgres": a[7], "git_sha": a[8], "date": a[9]}, indent=1))' \
    "$CERT_COUNT" "$search_p99" "$list_p95" "$issue_rps" "$issue_fail" "$rss" "$PG_VERSION" \
    "$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)" "$(date -u +%Y-%m-%dT%H:%M:%SZ)")"
  export RESULTS_JSON
}

perf_down() {
  set +e
  stop_hub
  if [[ -n "${PG_CONTAINER:-}" ]]; then
    "$ENGINE" rm -f "$PG_CONTAINER" >/dev/null 2>&1
    "$ENGINE" volume rm -f "$PG_VOLUME" >/dev/null 2>&1
  fi
  [[ -n "${WORK:-}" && -d "$WORK" ]] && rm -rf "$WORK"
  return 0
}

main() {
  local certs=100000 out="" nobar=0
  while (($#)); do
    case "$1" in
      --certs) certs="$2"; shift 2 ;;
      --out) out="$2"; shift 2 ;;
      --no-bar) nobar=1; shift ;;
      *) echo "usage: bench.sh [--certs N] [--no-bar] [--out DIR]" >&2; exit 64 ;;
    esac
  done
  [[ -n "$out" ]] || out="$(mktemp -d)"
  mkdir -p "$out"
  out="$(cd "$out" && pwd)"
  trap perf_down EXIT
  perf_up "$certs"
  perf_measure
  printf '%s\n' "$RESULTS_JSON" >"$out/results.json"
  if ((nobar)) || ((certs >= 1000000)); then
    log "published without a pass bar"
  fi
  log "wrote $out/results.json"
  cat "$out/results.json"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
