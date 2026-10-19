#!/usr/bin/env bash
# W19-12 (AWS leg, free): run the real AWS KMS code path against moto, an
# open-source AWS emulator, in a container. No AWS account, no cost.
# Covers the SDK wiring and wire formats, NOT IAM, quotas or real HSM
# behaviour -- those still need a real account (see README.md).
set -u -o pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
. "$HERE/../lib/podman.sh"
CE="${CONTAINER_ENGINE:-podman}"
NAME=kk-uat-moto
PORT="${KK_MOTO_PORT:-$(kk_free_port)}"
IMAGE="${KK_MOTO_IMAGE:-docker.io/motoserver/moto:latest}"
cleanup() { "$CE" rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

"$CE" rm -f "$NAME" >/dev/null 2>&1 || true
"$CE" image inspect "$IMAGE" >/dev/null 2>&1 || "$CE" pull "$IMAGE" >/dev/null || { echo "FAIL: pull $IMAGE"; exit 1; }
"$CE" run -d --name "$NAME" -p "127.0.0.1:${PORT}:5000" "$IMAGE" >/dev/null || { echo "FAIL: start moto"; exit 1; }
for _ in $(seq 1 30); do curl -sf "http://127.0.0.1:${PORT}/moto-api/" >/dev/null && break; sleep 1; done
curl -sf "http://127.0.0.1:${PORT}/moto-api/" >/dev/null || { echo "FAIL: moto never answered"; exit 1; }
echo "PASS: moto answering on :${PORT}"

# Throwaway placeholder credentials; moto does not validate them.
export AWS_ENDPOINT_URL="http://127.0.0.1:${PORT}" AWS_REGION=us-east-1 \
  AWS_ACCESS_KEY_ID=kk-uat AWS_SECRET_ACCESS_KEY=kk-uat KK_LIVE_KMS_AWS=1 KK_KMS_EMULATOR_MOTO=1
cd "$REPO_ROOT" && go test ./tests/live/kms-aws/ -count=1 -v 2>&1 | tee /tmp/kk-kms-aws.log
if [ "${PIPESTATUS[0]}" -eq 0 ]; then echo "ALL CHECKS PASSED"; else echo "FAIL: see above"; exit 1; fi
