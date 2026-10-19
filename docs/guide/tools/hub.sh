#!/usr/bin/env bash
# Start/stop a throwaway Kryptkeeper hub + production UI bundle server for guide capture.
#   RUN=<dir> BIN=<kryptkeeper binary> hub.sh start NAME HUBPORT UIPORT DATADIR
#   RUN=<dir> hub.sh stop NAME
# Persona via LOGIN_EMAIL / LOGIN_SUBJECT / LOGIN_ROLE (single password-login principal per hub process;
# restart on the same DATADIR to switch persona). Extra hub env: pass as EXTRA_ENV="A=1 B=2".
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
: "${RUN:?}"
cmd="$1"; name="$2"
case "$cmd" in
start)
  hubport="$3"; uiport="$4"; data="$5"; mkdir -p "$data" "$RUN"
  # the hub keeps some state files under ./var relative to cwd: give every hub its own cwd so "fresh" really is fresh
  mkdir -p "$data.cwd"; cd "$data.cwd"
  PW="${KK_PASSWORD:-GuideDemo!2026}"; PEPPER=devpepper
  HASH=$(python3 -c "import hmac,hashlib,sys;print(hmac.new(sys.argv[1].encode(),sys.argv[2].encode(),hashlib.sha256).hexdigest())" "$PEPPER" "$PW")
  env APP_CERTIFICATE_PROVIDER=ca KRYPTKEEPER_TLS_DISABLE=true KRYPTKEEPER_DATA_DIR="$data" \
    KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true KRYPTKEEPER_CA_NAME="Acme Root CA" \
    KRYPTKEEPER_KEYSTORE_PASSPHRASE=devpassphrase APP_BOOTSTRAP_TOKEN=dev-token \
    APP_AUTH_LOGIN_ENABLED=true APP_AUTH_LOGIN_EMAIL="${LOGIN_EMAIL:-ada.admin@acme.test}" \
    APP_AUTH_LOGIN_PASSWORD_PEPPER="$PEPPER" APP_AUTH_LOGIN_PASSWORD_HASH="$HASH" \
    APP_AUTH_LOGIN_SUBJECT="${LOGIN_SUBJECT:-ada.admin}" APP_AUTH_LOGIN_ROLE="${LOGIN_ROLE:-pki-admin}" \
    APP_AUTH_LOGIN_ACTIVE=true APP_AUTH_LOGIN_SIGNING_SECRET=dev-signing-secret-local-review-0123456789ab \
    APP_AUTH_ACCESS_TTL_SEC=86400 APP_AUTH_IDLE_TIMEOUT_SEC=86400 \
    APP_API_KEY_PEPPER=guide-pepper APP_API_KEY_AUTH_ENABLED=true \
    APP_NOTIFICATION_PROVIDER=delivery APP_DISCOVERY_PROVIDER=db SPIFFE_TRUST_DOMAIN=acme.test \
    ADDR=":$hubport" PORT="$hubport" ${EXTRA_ENV:-} \
    nohup "${BIN:?}" >"$RUN/$name.hub.log" 2>&1 &
  echo $! >"$RUN/$name.hub.pid"
  for i in $(seq 1 40); do curl -sf "http://127.0.0.1:$hubport/healthz" >/dev/null 2>&1 && break; sleep 0.5; done
  curl -s -o /dev/null -w "hub %{http_code}\n" "http://127.0.0.1:$hubport/healthz"
  if [ ! -f "$RUN/$name.ui.pid" ] || ! kill -0 "$(cat "$RUN/$name.ui.pid")" 2>/dev/null; then
    KK_REVIEW_API="http://127.0.0.1:$hubport" KK_REVIEW_PORT="$uiport" nohup node "$REPO/scripts/dev/serve-real.mjs" >"$RUN/$name.ui.log" 2>&1 &
    echo $! >"$RUN/$name.ui.pid"; sleep 1
  fi
  ;;
stop)
  what="${3:-all}"
  for k in hub ui; do
    [ "$what" = all ] || [ "$what" = "$k" ] || continue
    f="$RUN/$name.$k.pid"; [ -f "$f" ] && { kill "$(cat "$f")" 2>/dev/null || true; rm -f "$f"; }
  done ;;
esac
