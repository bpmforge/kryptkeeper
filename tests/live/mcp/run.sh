#!/usr/bin/env bash
# W29-08 live MCP E2E: the real kryptkeeper-mcp binary, driven by the official
# mark3labs/mcp-go client over stdio and StreamableHTTP, against a real hub
# process (host process, no containers). Proves propose_* -> human approve ->
# executed for all five propose tools, that the mcp-agent role can never
# approve, and that the server refuses to boot with an approver-capable token.
# Idempotent, non-zero exit on failure, always cleans up.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
WORK="$(mktemp -d /tmp/kk-uat-mcp.XXXXXX)"
HUB_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
TOKEN="uat-token"
EMAIL="live-approver@example.test"
PASSWORD="Live-Approver!2026"
PEPPER="live-pepper"
HUB_PID=""

log() { printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*"; }
cleanup() {
  [ -n "$HUB_PID" ] && kill "$HUB_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

log "building hub and kryptkeeper-mcp"
( cd "$ROOT" && go build -o "$WORK/kryptkeeper" ./cmd/kryptkeeper && go build -o "$WORK/kryptkeeper-mcp" ./cmd/kryptkeeper-mcp ) \
  || { log "FAIL: build"; exit 1; }

# The named administrator is the human approver: the bootstrap token and any
# key minted with it are setup credentials the hub refuses as approvers.
PASS_HASH="$(python3 -c "import hmac,hashlib,sys;print(hmac.new(sys.argv[1].encode(),sys.argv[2].encode(),hashlib.sha256).hexdigest())" "$PEPPER" "$PASSWORD")"
mkdir -p "$WORK/data"
log "starting hub on :$HUB_PORT"
APP_CERTIFICATE_PROVIDER=ca KRYPTKEEPER_TLS_DISABLE=true \
  APP_BOOTSTRAP_TOKEN="$TOKEN" AUTH_MODE=bootstrap \
  APP_DISCOVERY_PROVIDER=db APP_NOTIFICATION_PROVIDER=file \
  APP_CREDENTIAL_STORE_PASSPHRASE='uat-mcp-cred-passphrase-32-bytes!!' \
  KRYPTKEEPER_KEYSTORE_PASSPHRASE='uat-mcp-keystore-passphrase-32b!!' \
  KRYPTKEEPER_DATA_DIR="$WORK/data" \
  APP_CA_FILE="$WORK/data/cas.json" APP_TEMPLATE_FILE="$WORK/data/templates.json" \
  APP_CERTIFICATE_FILE="$WORK/data/certificates.json" APP_AUDIT_FILE="$WORK/data/audit.json" \
  APP_CERTS_SUMMARY_FILE="$WORK/data/certs_summary.json" \
  KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true KRYPTKEEPER_CA_NAME="UAT Root CA" \
  APP_AUTH_LOGIN_ENABLED=true APP_AUTH_LOGIN_EMAIL="$EMAIL" \
  APP_AUTH_LOGIN_PASSWORD_PEPPER="$PEPPER" APP_AUTH_LOGIN_PASSWORD_HASH="$PASS_HASH" \
  APP_AUTH_LOGIN_SUBJECT="live-human-approver" APP_AUTH_LOGIN_ROLE=pki-admin APP_AUTH_LOGIN_ACTIVE=true \
  APP_AUTH_LOGIN_SIGNING_SECRET='live-signing-secret-0123456789abcdef-xyz' \
  APP_API_KEY_AUTH_ENABLED=true APP_API_KEY_PEPPER='live-api-key-pepper-0123456789abcdef' \
  APP_BIND_ADDR=127.0.0.1 PORT="$HUB_PORT" \
  "$WORK/kryptkeeper" >"$WORK/hub.log" 2>&1 &
HUB_PID=$!

BASE="http://127.0.0.1:$HUB_PORT"
for _ in $(seq 1 45); do
  curl -fsS -o /dev/null "$BASE/api/v1/cas" -H "Authorization: Bearer $TOKEN" 2>/dev/null && break
  sleep 1
done
if ! curl -fsS -o /dev/null "$BASE/api/v1/cas" -H "Authorization: Bearer $TOKEN"; then
  log "FAIL: hub never answered /api/v1/cas"; tail -30 "$WORK/hub.log"; exit 1
fi
log "hub answering on $BASE"

cd "$ROOT" || exit 1
KK_LIVE_MCP=1 KK_MCP_HUB_BASE="$BASE" KK_MCP_ADMIN_TOKEN="$TOKEN" KK_MCP_BIN="$WORK/kryptkeeper-mcp" \
  KK_MCP_APPROVER_EMAIL="$EMAIL" KK_MCP_APPROVER_PASSWORD="$PASSWORD" \
  go test ./tests/live/mcp/... -count=1 -v 2>&1 | tee "$WORK/test.log"
RC=${PIPESTATUS[0]}

PASSED="$(grep -c -- '--- PASS' "$WORK/test.log")"
FAILED="$(grep -c -- '--- FAIL' "$WORK/test.log")"
echo
echo "=== W29-08 summary: $PASSED passed, $FAILED failed (go test exit $RC) ==="
if [ "$RC" -ne 0 ]; then echo "--- hub log tail ---"; tail -20 "$WORK/hub.log"; fi
exit $((RC != 0 || FAILED > 0))
