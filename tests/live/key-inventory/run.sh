#!/usr/bin/env bash
# W24-34: live unified key-inventory case. Starts an AWS KMS emulator (moto by
# default, KK_AWS_EMULATOR=localstack opt-in) and, with KK_KEYINV_AZURE=1, a
# Lowkey Vault Azure emulator, then runs the gated Go tests. GCP has no free
# KMS emulator and is skipped with a named reason. No cloud account, no cost.
set -u -o pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
. "$HERE/../lib/podman.sh"
CE="${CONTAINER_ENGINE:-podman}"
AWS_NAME=kk-uat-keyinv-aws
AZ_NAME=kk-uat-keyinv-lowkey
WORK="$(mktemp -d /tmp/kk-uat-keyinv.XXXXXX)"
cleanup() {
  "$CE" rm -f "$AWS_NAME" "$AZ_NAME" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
"$CE" rm -f "$AWS_NAME" "$AZ_NAME" >/dev/null 2>&1 || true

pull() { "$CE" image inspect "$1" >/dev/null 2>&1 || "$CE" pull "$1" >/dev/null || { echo "FAIL: pull $1"; exit 1; }; }

if [ "${KK_AWS_EMULATOR:-moto}" = "localstack" ]; then
  IMAGE="${KK_AWS_IMAGE:-docker.io/localstack/localstack:3}"; INNER=4566; PORT="${KK_LOCALSTACK_PORT:-$(kk_free_port)}"
  READY="http://127.0.0.1:${PORT}/_localstack/health"; EXTRA=(-e SERVICES=kms)
else
  IMAGE="${KK_AWS_IMAGE:-docker.io/motoserver/moto:latest}"; INNER=5000; PORT="${KK_MOTO_PORT:-$(kk_free_port)}"
  READY="http://127.0.0.1:${PORT}/moto-api/"; EXTRA=()
fi
pull "$IMAGE"
"$CE" run -d --name "$AWS_NAME" -p "127.0.0.1:${PORT}:${INNER}" ${EXTRA[@]+"${EXTRA[@]}"} "$IMAGE" >/dev/null || { echo "FAIL: start AWS emulator"; exit 1; }
for _ in $(seq 1 60); do curl -sf "$READY" >/dev/null && break; sleep 1; done
curl -sf "$READY" >/dev/null || { echo "FAIL: AWS emulator never answered"; exit 1; }
echo "PASS: AWS emulator (${KK_AWS_EMULATOR:-moto}) answering on :${PORT}"

# Throwaway placeholder credentials; the emulators do not validate them.
export AWS_ENDPOINT_URL="http://127.0.0.1:${PORT}" AWS_REGION=us-east-1 \
  AWS_ACCESS_KEY_ID=kk-uat AWS_SECRET_ACCESS_KEY=kk-uat KK_LIVE_KEYINV=1

if [ "${KK_KEYINV_AZURE:-0}" = "1" ]; then
  AZ_IMAGE="${KK_LOWKEY_IMAGE:-docker.io/nagyesta/lowkey-vault:7.3.112}"; VPORT="${KK_LOWKEY_PORT:-8443}"
  pull "$AZ_IMAGE"
  "$CE" run -d --name "$AZ_NAME" -p "127.0.0.1:${VPORT}:8443" "$AZ_IMAGE" >/dev/null || { echo "FAIL: start lowkey-vault"; exit 1; }
  for _ in $(seq 1 180); do curl -sfk "https://localhost:${VPORT}/ping" >/dev/null && break; sleep 2; done  # amd64 image under emulation on arm64 takes ~3 min
  curl -sfk "https://localhost:${VPORT}/ping" >/dev/null || { echo "FAIL: lowkey-vault never answered"; exit 1; }
  echo "PASS: lowkey-vault answering on :${VPORT}"
  openssl s_client -connect "localhost:${VPORT}" -servername localhost </dev/null 2>/dev/null \
    | openssl x509 >"$WORK/lowkey.pem" || { echo "FAIL: could not read emulator cert"; exit 1; }
  export SSL_CERT_FILE="$WORK/lowkey.pem" KK_KEYINV_AZURE_URL="https://localhost:${VPORT}"
fi

cd "$REPO_ROOT" && go test ./tests/live/key-inventory/ -count=1 -v 2>&1 | tee "$WORK/test.log"
rc=${PIPESTATUS[0]}
echo "--- skips (named, never silent) ---"; grep -E '^\s+keyinventory_live_test.go:[0-9]+: (set|no |KK_)' "$WORK/test.log" | grep -v 'set KK_LIVE_KEYINV=1' || true
if [ "$rc" -eq 0 ]; then echo "ALL CHECKS PASSED"; else echo "FAIL: see above"; exit 1; fi
