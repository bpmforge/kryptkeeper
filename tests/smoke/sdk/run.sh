#!/usr/bin/env bash
# W32-03: SDK contract smoke against a live hub built from this checkout.
#
# Builds the hub, starts it on a free port, seeds a template and 5 CSRs, then
# runs the generated Go, TypeScript and Python SDKs (sdk/api-*) through:
# issue 5 certificates, list across >= 2 pages, revoke one. One PASS/FAIL line
# per SDK; any FAIL -> exit 1.
#
# Prerequisite (CI order): `bash scripts/gen-sdks.sh --check` already ran.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SMOKE_DIR="$ROOT_DIR/tests/smoke/sdk"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/kkw32-sdk-smoke.XXXXXX")"
HUB_PID=""

# ONE top-level trap (see tests/smoke/run.sh W19-21): no per-function locals.
cleanup() {
  [ -n "$HUB_PID" ] && kill "$HUB_PID" >/dev/null 2>&1 || true
  [ -n "$HUB_PID" ] && wait "$HUB_PID" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

die() { echo "[sdk-smoke] FAIL $*" >&2; exit 1; }

for l in go ts py; do
  [ -d "$ROOT_DIR/sdk/api-$l" ] && [ -n "$(ls -A "$ROOT_DIR/sdk/api-$l" 2>/dev/null)" ] ||
    die "sdk/api-$l missing: run 'bash scripts/gen-sdks.sh --check' first"
done
[ -f "$ROOT_DIR/sdk/api-go/api_certificates.go" ] || die "sdk/api-go not generated: run scripts/gen-sdks.sh first"
for t in go node npm npx python3 openssl curl; do
  command -v "$t" >/dev/null 2>&1 || die "required tool not found: $t"
done

PORT="$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)"
# Secrets travel via env only, never argv (visible to ps).
TOKEN="sdk-smoke-$(openssl rand -hex 16)"
HUB_URL="http://127.0.0.1:${PORT}"

echo "[sdk-smoke] building hub"
(cd "$ROOT_DIR" && go build -o "$WORK/kryptkeeper" ./cmd/kryptkeeper)

mkdir -p "$WORK/data"
(
  export APP_BOOTSTRAP_TOKEN="$TOKEN" AUTH_MODE=bootstrap APP_CERTIFICATE_PROVIDER=ca \
    KRYPTKEEPER_TLS_DISABLE=true \
    KRYPTKEEPER_KEYSTORE_PASSPHRASE='sdk-smoke-keystore-passphrase-32b!!' \
    APP_CREDENTIAL_STORE_PASSPHRASE='sdk-smoke-cred-passphrase-32-bytes!!' \
    KRYPTKEEPER_DATA_DIR="$WORK/data" \
    APP_CA_FILE="$WORK/data/cas.json" \
    APP_TEMPLATE_FILE="$WORK/data/templates.json" \
    APP_CERTIFICATE_FILE="$WORK/data/certificates.json" \
    APP_AUDIT_FILE="$WORK/data/audit.json" \
    APP_CERTS_SUMMARY_FILE="$WORK/data/certs_summary.json" \
    KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true KRYPTKEEPER_CA_NAME="SDK Smoke Root CA" \
    APP_BIND_ADDR=127.0.0.1 PORT="$PORT"
  exec "$WORK/kryptkeeper" >"$WORK/hub.log" 2>&1
) &
HUB_PID=$!

tries=30
until curl -sSf -o /dev/null "$HUB_URL/readyz" 2>/dev/null; do
  kill -0 "$HUB_PID" 2>/dev/null || { cat "$WORK/hub.log" >&2; die "hub exited during startup"; }
  tries=$((tries - 1))
  [ "$tries" -gt 0 ] || { tail -20 "$WORK/hub.log" >&2; die "hub not ready on $HUB_URL within 30s"; }
  sleep 1
done
echo "[sdk-smoke] hub ready on $HUB_URL"

# curl auth header via a config file on stdin-free path: keep token out of argv.
printf 'header = "Authorization: Bearer %s"\nheader = "Content-Type: application/json"\n' "$TOKEN" > "$WORK/curl.cfg"
chmod 600 "$WORK/curl.cfg"
curlj() { curl -sS -K "$WORK/curl.cfg" "$@"; }

CA_ID="$(curlj "$HUB_URL/api/v1/cas" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"][0]["id"])')" ||
  die "could not list CAs"
[ -n "$CA_ID" ] || die "no CA found (see hub.log)"

TEMPLATE_ID="$(curlj -X POST "$HUB_URL/api/v1/templates" -d '{
  "name": "sdk-smoke",
  "display_name": "SDK smoke (no approval)",
  "allowed_algorithms": ["ECDSA"],
  "key_usage": ["digitalSignature", "keyEncipherment"],
  "extended_key_usage": ["serverAuth"],
  "validity_period": "48h",
  "active": true
}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["id"])')" || die "template create failed"
[ -n "$TEMPLATE_ID" ] || die "template create returned no id"

# Each SDK gets its own CSR set: re-submitting the same key + template makes
# the hub return the existing certificate with 200 (W26-32), not 201.
for l in go ts py; do
  mkdir -p "$WORK/csr-$l"
  for n in 1 2 3 4 5; do
    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
      -keyout "$WORK/csr-$l/key-$n.pem" -out "$WORK/csr-$l/csr-$n.pem" \
      -subj "/CN=sdk-$l-$n.test" -addext "subjectAltName=DNS:sdk-$l-$n.test" >/dev/null 2>&1
  done
done

export HUB_URL CA_ID TEMPLATE_ID
export HUB_TOKEN="$TOKEN"

FAILED=0
run_smoke() { # name, command...
  local name="$1"; shift
  export CSR_DIR="$WORK/csr-$name"
  if "$@" >"$WORK/$name.out" 2>&1; then
    echo "[sdk-smoke] PASS $name -- $(tail -1 "$WORK/$name.out")"
  else
    echo "[sdk-smoke] FAIL $name"
    sed 's/^/    /' "$WORK/$name.out" >&2
    FAILED=1
  fi
}

# Go: separate module with a replace onto sdk/api-go.
(cd "$SMOKE_DIR/go" && go mod tidy >/dev/null 2>&1 || true)
run_smoke go bash -c 'cd "$1" && go run .' _ "$SMOKE_DIR/go"

# TypeScript: tsx pinned in tests/smoke/sdk/ts/package.json.
run_smoke ts bash -c 'cd "$1" && npm install --no-audit --no-fund --silent && npx --no-install tsx smoke.ts' _ "$SMOKE_DIR/ts"

# Python: generated package installed into a throwaway venv.
run_smoke py bash -c 'python3 -m venv "$1/venv" && "$1/venv/bin/pip" install --quiet "$2" && "$1/venv/bin/python" "$3"' \
  _ "$WORK" "$ROOT_DIR/sdk/api-py" "$SMOKE_DIR/py/smoke.py"

[ "$FAILED" -eq 0 ] || { echo "[sdk-smoke] FAILED (hub log: $WORK/hub.log, removed on exit)" >&2; tail -20 "$WORK/hub.log" >&2; exit 1; }
echo "[sdk-smoke] OK 3/3 SDKs (go, ts, py)"
