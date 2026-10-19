#!/usr/bin/env bash
# Stand up a local backend for UI review, against the real CA engine.
#
# Why this exists: the login password is verified as HMAC-SHA256(pepper,
# password) hex (internal/bootstrap/auth_identity.go), NOT bcrypt, and the
# server needs APP_AUTH_LOGIN_PASSWORD_HASH rather than a plaintext password.
# That is not guessable, and rediscovering it costs real time.
#
#   ./scripts/dev/local-review-env.sh start   # backend on :8080
#   ./scripts/dev/local-review-env.sh token   # print a fresh access token
#
# Then serve the PRODUCTION UI bundle, never `npm run dev` — main.tsx starts MSW
# whenever import.meta.env.DEV, so the dev server answers from
# ui/src/mocks/fixtures.ts (247 certificates that do not exist) and accepts any
# credentials. Anything reviewed there documents fixtures, not the product.
#
# TLS is off by default here: ca mode self-issues a TLS listener since W19-14,
# but `vite preview` proxies /api to plain http://localhost:8080.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DATA_DIR="${KK_DEV_DATA_DIR:-/tmp/kk-dev-data}"
EMAIL="${KK_DEV_EMAIL:-demo@example.com}"
PASSWORD="${KK_DEV_PASSWORD:-GuideDemo!2026}"
PEPPER="${KK_DEV_PEPPER:-devpepper}"
PORT="${KK_DEV_PORT:-8080}"

hash_password() {
  python3 -c "import hmac,hashlib,sys;print(hmac.new(sys.argv[1].encode(),sys.argv[2].encode(),hashlib.sha256).hexdigest())" \
    "$PEPPER" "$PASSWORD"
}

case "${1:-start}" in
start)
  cd "$REPO"
  go build -o dist/kryptkeeper ./cmd/kryptkeeper
  pkill -f 'dist/kryptkeeper' 2>/dev/null || true
  sleep 1
  mkdir -p "$DATA_DIR"
  APP_CERTIFICATE_PROVIDER=ca \
  KRYPTKEEPER_TLS_DISABLE="${KRYPTKEEPER_TLS_DISABLE:-true}" \
  KRYPTKEEPER_DATA_DIR="$DATA_DIR" \
  KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true \
  KRYPTKEEPER_CA_NAME="${KK_DEV_CA_NAME:-Dev Root CA}" \
  KRYPTKEEPER_KEYSTORE_PASSPHRASE="${KK_DEV_KEYSTORE_PASS:-devpassphrase}" \
  APP_BOOTSTRAP_TOKEN="${KK_DEV_BOOTSTRAP_TOKEN:-dev-token}" \
  APP_AUTH_LOGIN_ENABLED=true \
  APP_AUTH_LOGIN_EMAIL="$EMAIL" \
  APP_AUTH_LOGIN_PASSWORD_PEPPER="$PEPPER" \
  APP_AUTH_LOGIN_PASSWORD_HASH="$(hash_password)" \
  APP_AUTH_LOGIN_SUBJECT="${KK_DEV_SUBJECT:-demo-operator}" \
  APP_AUTH_LOGIN_ROLE="${KK_DEV_ROLE:-pki-admin}" \
  APP_AUTH_LOGIN_ACTIVE=true \
  APP_AUTH_LOGIN_SIGNING_SECRET="${KK_DEV_SIGNING_SECRET:-dev-signing-secret-local-review-0123456789ab}" \
  nohup ./dist/kryptkeeper > /tmp/kk-dev-server.log 2>&1 &
  sleep 3
  printf 'api :%s -> %s\n' "$PORT" "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/healthz")"
  echo "log: /tmp/kk-dev-server.log"
  ;;
token)
  # The access token lives 900s and nothing consumes the refresh token (S-38),
  # so re-run this before each batch of work.
  curl -s -X POST "http://127.0.0.1:$PORT/api/v1/auth/login" \
    -H 'content-type: application/json' \
    -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["data"]["access_token"])'
  ;;
*)
  echo "usage: $0 {start|token}" >&2
  exit 2
  ;;
esac
