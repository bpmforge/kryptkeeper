#!/usr/bin/env bash
set -uo pipefail

# filename: tests/integration/tenant_idor/run.sh
#
# W22-02: cross-tenant IDOR suite. Boots a real hub (MULTI_TENANCY=on) per DB
# engine, replays every docs/openapi.yaml operation as 4 roles of tenant acme
# against tenant globex's seeded data, and exits non-zero on any leak. A
# self-test then proves the suite fails closed against a seeded leak.
#
#   bash scripts/test/run.sh --suite tenant-idor
#
# Env: KRYPTKEEPER_TEST_POSTGRES_DSN (db name must contain "test") enables the
# postgres pass; KK_IDOR_REQUIRE_POSTGRES=1 turns its absence into a failure.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/kk-idor-XXXXXX")"
HUB_PID=""
summaries=()
status=0

stop_hub() {
  if [[ -n "$HUB_PID" ]]; then
    kill "$HUB_PID" >/dev/null 2>&1 || true
    wait "$HUB_PID" >/dev/null 2>&1 || true
    HUB_PID=""
  fi
}
cleanup() { stop_hub; rm -rf "$WORK"; }
trap cleanup EXIT INT TERM

free_port() {
  python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])' 2>/dev/null \
    || ruby -rsocket -e 's=TCPServer.new("127.0.0.1",0);puts s.addr[1]'
}

# Routes come from the spec, never from a hand list, so a new route is probed
# the day it is documented. Fails closed when no parser is available.
extract_routes() {
  if command -v ruby >/dev/null 2>&1; then
    ruby -ryaml -e '
      y = YAML.load_file(ARGV[0])
      base = ((y["servers"] || [{}]).first || {})["url"].to_s.sub(%r{/\z}, "")
      y["paths"].each do |path, ops|
        srv = ((ops["servers"] || []).first || {})["url"]
        prefix = srv.nil? ? base : srv.to_s.sub(%r{/\z}, "")
        %w[get post put patch delete].each do |m|
          puts "#{m.upcase}\t#{prefix}#{path}" if ops.key?(m)
        end
      end' "$ROOT_DIR/docs/openapi.yaml" >"$WORK/routes.tsv"
  elif command -v python3 >/dev/null 2>&1 && python3 -c 'import yaml' 2>/dev/null; then
    python3 - "$ROOT_DIR/docs/openapi.yaml" >"$WORK/routes.tsv" <<'PY'
import sys, yaml
y = yaml.safe_load(open(sys.argv[1]))
base = (y.get("servers") or [{}])[0].get("url", "").rstrip("/")
for path, ops in y["paths"].items():
    srv = (ops.get("servers") or [{}])[0].get("url")
    prefix = base if srv is None else srv.rstrip("/")
    for m in ("get", "post", "put", "patch", "delete"):
        if m in ops:
            print(f"{m.upper()}\t{prefix}{path}")
PY
  else
    echo "[tenant-idor] FAIL no ruby or python3+yaml to parse docs/openapi.yaml" >&2
    return 1
  fi
  [[ -s "$WORK/routes.tsv" ]] || { echo "[tenant-idor] FAIL no routes extracted" >&2; return 1; }
}

run_engine() {
  local engine="$1" port token data_dir rc line
  port="$(free_port)"
  token="idor-$(openssl rand -hex 16)"
  data_dir="$WORK/data-$engine"
  mkdir -p "$data_dir"

  local -a env=(
    PORT="$port" APP_BIND_ADDR=127.0.0.1
    APP_CERTIFICATE_PROVIDER=ca KRYPTKEEPER_TLS_DISABLE=true
    KRYPTKEEPER_DATA_DIR="$data_dir" KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true
    KRYPTKEEPER_CA_NAME="IDOR Root" KRYPTKEEPER_KEYSTORE_PASSPHRASE="idor-$(openssl rand -hex 12)"
    APP_BOOTSTRAP_TOKEN="$token" AUTH_MODE=bootstrap
    MULTI_TENANCY=on
    APP_API_KEY_AUTH_ENABLED=true APP_API_KEY_PEPPER="idor-$(openssl rand -hex 20)"
  )
  if [[ "$engine" == postgres ]]; then
    env+=(KRYPTKEEPER_DB_MODE=postgres KRYPTKEEPER_DB_DSN="$KRYPTKEEPER_TEST_POSTGRES_DSN")
    # A previous run's CAs have no key in this run's fresh keystore, so the
    # hub would refuse to start; begin from an empty schema every time.
    if ! (cd "$ROOT_DIR" && KK_IDOR_RESET_PG=1 go test ./tests/integration/tenant_idor/ -run TestResetPostgres -count=1 >"$WORK/pg-reset.log" 2>&1); then
      echo "[tenant-idor] FAIL engine=postgres could not reset the test database:" >&2
      tail -5 "$WORK/pg-reset.log" >&2
      return 1
    fi
  fi

  env "${env[@]}" "$WORK/kryptkeeper" >"$WORK/hub-$engine.log" 2>&1 &
  HUB_PID=$!

  local i ready=0
  for i in $(seq 1 60); do
    if curl -fsS "http://127.0.0.1:$port/healthz" >/dev/null 2>&1; then ready=1; break; fi
    kill -0 "$HUB_PID" 2>/dev/null || break
    sleep 0.5
  done
  if [[ "$ready" != 1 ]]; then
    echo "[tenant-idor] FAIL engine=$engine hub did not become healthy; log tail:" >&2
    tail -20 "$WORK/hub-$engine.log" >&2
    stop_hub
    return 1
  fi

  rm -f "$WORK/summary-$engine"
  (cd "$ROOT_DIR" && \
    KK_IDOR_BASE_URL="http://127.0.0.1:$port" KK_IDOR_BOOTSTRAP_TOKEN="$token" \
    KK_IDOR_ROUTES="$WORK/routes.tsv" KK_IDOR_ENGINE="$engine" \
    KK_IDOR_SUMMARY_FILE="$WORK/summary-$engine" \
    go test ./tests/integration/tenant_idor/ -run TestTenantIDOR -count=1 -v)
  rc=$?
  stop_hub

  line="$(cat "$WORK/summary-$engine" 2>/dev/null || echo "routes=? requests=? leaks=? elapsed=?")"
  # routes= requests= leaks= elapsed= -> final summary line shape from the spec.
  summaries+=("[tenant-idor] engine=$engine ${line% *} elapsed=${line##*elapsed=}s")
  return "$rc"
}

# Self-test: the suite must fail closed. The detector unit test proves a
# seeded leak is reported; the harness pointed at the leaky fixture hub must
# exit non-zero. A zero exit here means the suite cannot be trusted.
self_test() {
  echo "[tenant-idor] self-test: seeded leak must be detected"
  if ! (cd "$ROOT_DIR" && go test ./tests/integration/tenant_idor/ -run 'TestSeededLeakIsDetected|TestDetect' -count=1); then
    echo "[tenant-idor] FAIL self-test: detector unit tests" >&2
    return 1
  fi
  if (cd "$ROOT_DIR" && KK_IDOR_LEAK_FIXTURE=1 KK_IDOR_SUMMARY_FILE="$WORK/summary-leak" \
        go test ./tests/integration/tenant_idor/ -run TestTenantIDOR -count=1 >"$WORK/leak.log" 2>&1); then
    echo "[tenant-idor] FAIL self-test: harness exited 0 against a deliberately leaky hub" >&2
    return 1
  fi
  grep -E 'LEAK ' "$WORK/leak.log" | head -2 | sed 's/^/[tenant-idor]   /'
  echo "[tenant-idor] self-test PASS: harness exited non-zero on the seeded leak ($(cat "$WORK/summary-leak" 2>/dev/null))"
}

echo "[tenant-idor] building hub"
(cd "$ROOT_DIR" && go build -o "$WORK/kryptkeeper" ./cmd/kryptkeeper) || { echo "[tenant-idor] FAIL build" >&2; exit 1; }
extract_routes || exit 1
echo "[tenant-idor] routes extracted: $(wc -l <"$WORK/routes.tsv" | tr -d ' ')"

run_engine sqlite || status=1

if [[ -n "${KRYPTKEEPER_TEST_POSTGRES_DSN:-}" ]]; then
  run_engine postgres || status=1
else
  echo "SKIP postgres (KRYPTKEEPER_TEST_POSTGRES_DSN not set)"
  if [[ "${KK_IDOR_REQUIRE_POSTGRES:-0}" == 1 ]]; then
    echo "[tenant-idor] FAIL postgres required (KK_IDOR_REQUIRE_POSTGRES=1) but no DSN" >&2
    status=1
  fi
fi

self_test || status=1

printf '%s\n' "${summaries[@]}"
if [[ "$status" -ne 0 ]]; then
  echo "[tenant-idor] FAIL" >&2
fi
exit "$status"
