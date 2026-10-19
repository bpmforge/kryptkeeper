#!/usr/bin/env bash
# Shared fixture for the W23-37 (ca-revoke) and W23-41 (key-compromise) live
# drills. Sourced, never run. A real hub (linux binary built from this
# checkout) runs in a podman container on a private network next to a
# throwaway Postgres; clients (lego, globalsign/est, micromdm/scep, openssl
# cmp) run in sibling containers on the same network. Two pki-admin humans and
# a third pki-admin outsider come from APP_API_KEYS_JSON (never the bootstrap
# token, which resolves to one shared human and breaks dual control).
#
# Caller sets before sourcing: FX_PREFIX (container/network name prefix),
# FX_PORT (host loopback port published for the hub API), RECORD (record file).
#
# Everything under $FX_RUN must live below $HOME: podman machine on macOS only
# virtiofs-mounts /Users.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib/podman.sh"
KK_RM_TIMEOUT=0   # throwaway hub/Postgres: no grace period (as the old fx_rm did)
FX_PREFIX="${FX_PREFIX:?}"
FX_PORT="${FX_PORT:?}"
FX_NET="${FX_PREFIX}-net"
FX_HUB="${FX_PREFIX}-hub"
FX_PG="${FX_PREFIX}-pg"
FX_RUN="${FX_RUN:-$HOME/.${FX_PREFIX}-run}"
FX_HUBPORT=8080
FX_REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
HUBURL="https://localhost:${FX_PORT}"
PEPPER="uat-pepper-32-characters-minimum!!"
PG_PASS="uat-$(openssl rand -hex 8)"
FAILED=0
# FX_DB_MODE=sqlite runs the hub on its embedded SQLite instead of Postgres. Postgres is the
# product's deployment mode and the default; sqlite exists to exercise the rest of a scenario
# when a Postgres-only defect (see RESULTS.md) blocks it. Records say which mode they used.
FX_DB_MODE="${FX_DB_MODE:-postgres}"
if [ "$FX_DB_MODE" = sqlite ]; then
  FX_DB_ARGS=(-e KRYPTKEEPER_DB_MODE=sqlite)
else
  FX_DB_ARGS=(-e KRYPTKEEPER_DB_MODE=postgres -e "DATABASE_URL=postgres://kryptkeeper:$PG_PASS@$FX_PG:5432/kryptkeeper?sslmode=disable")
fi
RECORD="${RECORD:-/dev/null}"

say()  { echo "$*" | tee -a "$RECORD"; }
STEP() { say ""; say "=== $* ==="; }
PASS() { say "PASS: $*"; }
# The drills stop at the first FAIL (the later steps depend on it); KK_KEEP_GOING=1 runs on.
FAIL() { say "FAIL: $*"; FAILED=1; [ "${KK_KEEP_GOING:-0}" = 1 ] || exit 1; }
DIE()  { say "FAIL: $*"; FAILED=1; exit 1; }
SKIP() { say "SKIPPED: $*"; }
jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }

fx_cleanup() {
  if [ "$FAILED" = 1 ]; then
    { echo; echo "--- hub log, last 40 lines at the failure ---"; podman logs --tail 40 "$FX_HUB" 2>&1; } | tee -a "$RECORD"
  fi
  kk_rm "$FX_HUB" "$FX_PG" ${FX_EXTRA_CONTAINERS:-}
  podman network rm "$FX_NET" >/dev/null 2>&1
  rm -rf "$FX_RUN"
}

# code TOKEN curl-args... -> prints the HTTP status, body in $FX_RUN/last.json
code() { local tok="$1"; shift; curl -sS --cacert "$FX_RUN/tls-export/ca.pem" -o "$FX_RUN/last.json" -w '%{http_code}' -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' "$@"; }
check() { if [ "$2" = "$3" ]; then PASS "$1 -> $3"; else FAIL "$1: want $2, got $3 ($(head -c 300 "$FX_RUN/last.json" 2>/dev/null))"; fi; }
ENTRIES=""
mkident() { # name role -> sets T_<name>
  local name="$1" role="$2" secret verifier
  secret="$(openssl rand -hex 24)"
  verifier="$(printf '%s' "$secret" | openssl dgst -sha256 -hmac "$PEPPER" -hex | awk '{print $NF}')"
  eval "T_$name=kk_uat${name}_${secret}"
  ENTRIES="${ENTRIES:+$ENTRIES,}{\"name\":\"$name\",\"kid\":\"uat$name\",\"secret_verifier\":\"$verifier\",\"principal_id\":\"$name\",\"role\":\"$role\",\"active\":true}"
}

fx_header() { # title
  : >"$RECORD"
  say "$1"
  say "date:    $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  say "commit:  $(git -C "$FX_REPO" rev-parse HEAD) ($(git -C "$FX_REPO" describe --tags --always 2>/dev/null))"
  say "db:      $FX_DB_MODE"
  say "mode:    $([ "${KK_KEEP_GOING:-0}" = 1 ] && echo 'keep-going (runs every step after a FAIL)' || echo 'stop at first FAIL')"
  say "machine: $(uname -srm), $(go version | awk '{print $3}'), podman $(podman --version | awk '{print $NF}'), $(openssl version | awk '{print $1" "$2}')"
}

fx_build_and_db() {
  STEP "build hub (linux/arm64) and start Postgres"
  mkdir -p "$FX_RUN/bin" "$FX_RUN/data" "$FX_RUN/tls-export" "$FX_RUN/work"
  (cd "$FX_REPO" && GOOS=linux GOARCH="$(kk_goarch)" CGO_ENABLED=0 go build -o "$FX_RUN/bin/kryptkeeper" ./cmd/kryptkeeper) || DIE "go build failed"
  PASS "hub built from this checkout"
  kk_rm "$FX_HUB" "$FX_PG"; podman network rm "$FX_NET" >/dev/null 2>&1
  podman network create "$FX_NET" >/dev/null || DIE "network create"
  podman run -d --name "$FX_PG" --network "$FX_NET" -e POSTGRES_PASSWORD="$PG_PASS" -e POSTGRES_DB=kryptkeeper -e POSTGRES_USER=kryptkeeper \
    postgres:16-alpine >/dev/null || DIE "postgres start"
  # -h 127.0.0.1: the image first runs a socket-only initdb server that pg_isready accepts, then
  # restarts; only the final server listens on TCP.
  for _ in $(seq 1 60); do podman exec "$FX_PG" pg_isready -h 127.0.0.1 -U kryptkeeper -d kryptkeeper >/dev/null 2>&1 && break; sleep 1; done
  podman exec "$FX_PG" pg_isready -h 127.0.0.1 -U kryptkeeper -d kryptkeeper >/dev/null 2>&1 || DIE "postgres never became ready"
  PASS "postgres ready on network $FX_NET"
}

# fx_start_hub [-e K=V ...]: (re)create the hub container; extra podman args pass through.
fx_start_hub() {
  kk_rm "$FX_HUB"
  podman run -d --name "$FX_HUB" --network "$FX_NET" --hostname "$FX_HUB" -p "127.0.0.1:${FX_PORT}:${FX_HUBPORT}" \
    -v "$FX_RUN/bin/kryptkeeper:/kryptkeeper:ro" -v "$FX_RUN/data:/data" -v "$FX_RUN/tls-export:/tls-export" \
    -v "$FX_REPO/tests/live/protocols/est-users.json:/est-users.json:ro" \
    -e APP_BOOTSTRAP_TOKEN="uat-bootstrap-$(openssl rand -hex 6)" -e AUTH_MODE=bootstrap -e APP_CERTIFICATE_PROVIDER=ca \
    -e APP_DISCOVERY_PROVIDER=db -e APP_NOTIFICATION_PROVIDER=file \
    -e APP_API_KEY_AUTH_ENABLED=true -e APP_API_KEY_PEPPER="$PEPPER" -e APP_API_KEYS_JSON="[$ENTRIES]" \
    -e APP_CREDENTIAL_STORE_PASSPHRASE='uat-cred-passphrase-32-bytes-long!!' \
    -e KRYPTKEEPER_KEYSTORE_PASSPHRASE='uat-keystore-passphrase-32-bytes!!' \
    -e KRYPTKEEPER_DATA_DIR=/data -e KRYPTKEEPER_KEYSTORE_DIR=/data/keystore \
    -e APP_CA_FILE=/data/cas.json -e APP_TEMPLATE_FILE=/data/templates.json -e APP_CERTIFICATE_FILE=/data/certificates.json \
    -e APP_AUDIT_FILE=/data/audit.json -e APP_CERTS_SUMMARY_FILE=/data/certs_summary.json \
    "${FX_DB_ARGS[@]}" \
    -e KRYPTKEEPER_TLS_SELF_ISSUE=true -e KRYPTKEEPER_TLS_SANS="$FX_HUB,localhost,127.0.0.1" -e KRYPTKEEPER_TLS_TRUST_EXPORT_DIR=/tls-export \
    -e KRYPTKEEPER_TLS_REQUEST_CLIENT_CERT=true \
    -e KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true -e KRYPTKEEPER_CA_NAME="UAT Root R" \
    -e APP_BIND_ADDR=0.0.0.0 -e PORT="$FX_HUBPORT" -e KRYPTKEEPER_BASE_URL="https://$FX_HUB:$FX_HUBPORT" \
    -e KRYPTKEEPER_EST_USERS_FILE=/est-users.json \
    -e KRYPTKEEPER_REVOCATION_SYNC_INTERVAL=1s \
    "$@" alpine:3 /kryptkeeper >/dev/null || return 1
  for _ in $(seq 1 60); do
    [ -s "$FX_RUN/tls-export/ca.pem" ] && curl -sf --cacert "$FX_RUN/tls-export/ca.pem" "$HUBURL/healthz" >/dev/null 2>&1 && return 0
    [ "$(podman inspect -f '{{.State.Running}}' "$FX_HUB" 2>/dev/null)" = true ] || return 1
    sleep 1
  done
  return 1
}

# CA/cert helpers (admin token passed explicitly).
fx_template() { # token -> sets TPL_ID
  TPL_ID="$(curl -sS --cacert "$FX_RUN/tls-export/ca.pem" -H "Authorization: Bearer $1" -H 'Content-Type: application/json' -X POST "$HUBURL/api/v1/templates" \
    -d '{"name":"uat-leaf","display_name":"UAT leaf","validity_period":"P30D","key_usage":["digitalSignature"],"extended_key_usage":["serverAuth"],"allowed_algorithms":["ECDSA"],"active":true}' | jget 'd["data"]["id"]')"
  [ -n "$TPL_ID" ]
}
# fx_issue TOKEN CA_ID CN OUTBASE -> HTTP code; writes OUTBASE.pem (leaf), OUTBASE.key, OUTBASE.fp (fingerprint)
fx_issue() {
  local tok="$1" ca="$2" cn="$3" out="$4" c
  openssl ecparam -name prime256v1 -genkey -noout -out "$out.key" 2>/dev/null
  openssl req -new -key "$out.key" -subj "/CN=$cn" -addext "subjectAltName=DNS:$cn" -out "$out.csr" 2>/dev/null
  python3 -c "import json,sys; json.dump({'ca_id':sys.argv[1],'template_id':sys.argv[2],'csr_pem':open(sys.argv[3]).read()}, open(sys.argv[4],'w'))" \
    "$ca" "$TPL_ID" "$out.csr" "$out.json"
  c=$(code "$tok" -X POST "$HUBURL/api/v1/certificates" --data @"$out.json")
  if [ "$c" = 201 ]; then
    # Runs in a $(...) subshell at the call site, so the fingerprint goes to a file.
    jget 'd["data"]["fingerprint_sha256"]' <"$FX_RUN/last.json" >"$out.fp"
    LAST_FP="$(cat "$out.fp")"
    curl -sS --cacert "$FX_RUN/tls-export/ca.pem" -H "Authorization: Bearer $tok" "$HUBURL/api/v1/certificates/$LAST_FP/download?format=pem" -o "$out.pem"
  fi
  echo "$c"
}
# ocsp_status ISSUER.pem LEAF.pem CAFILE -> prints good|revoked|unknown|error
ocsp_status() {
  local out
  out="$(openssl ocsp -issuer "$1" -cert "$2" -url "$HUBURL/ocsp" -CAfile "$3" -no_nonce 2>&1)"
  if echo "$out" | grep -q ': revoked'; then echo revoked
  elif echo "$out" | grep -q ': good'; then echo good
  elif echo "$out" | grep -q ': unknown'; then echo unknown
  else echo "error: $(echo "$out" | head -c 200 | tr '\n' ' ')"; fi
}
# poll_ocsp WANT SECS ISSUER LEAF CAFILE -> 0 if WANT seen within SECS (poll 2s); sets POLL_ELAPSED
poll_ocsp() {
  local want="$1" secs="$2" start now st
  start=$(date +%s)
  while :; do
    st="$(ocsp_status "$3" "$4" "$5")"
    now=$(date +%s); POLL_ELAPSED=$((now-start))
    [ "$st" = "$want" ] && return 0
    [ "$POLL_ELAPSED" -ge "$secs" ] && { POLL_LAST="$st"; return 1; }
    sleep 2
  done
}
