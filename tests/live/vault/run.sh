#!/usr/bin/env bash
# W23-14: run the real VaultStore (transit) against a Vault dev server in a
# container. Proves the transit wire formats (key create/read, sign, delete);
# NOT auth policies, namespaces, HA or a production seal. Throwaway dev token.
set -u -o pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
CE="${CONTAINER_ENGINE:-podman}"
NAME=kk-uat-vault
PORT="${KK_VAULT_PORT:-8200}"
IMAGE="${KK_VAULT_IMAGE:-docker.io/hashicorp/vault:1.17}"
TOKEN=kk-uat
ADDR="http://127.0.0.1:${PORT}"
LOG="$(mktemp -t kk-vault-live.XXXXXX)"
cleanup() { "$CE" rm -f "$NAME" >/dev/null 2>&1 || true; rm -f "$LOG"; }
trap cleanup EXIT

"$CE" rm -f "$NAME" >/dev/null 2>&1 || true
"$CE" image inspect "$IMAGE" >/dev/null 2>&1 || "$CE" pull "$IMAGE" >/dev/null || { echo "FAIL: pull $IMAGE"; exit 1; }
"$CE" run -d --name "$NAME" --cap-add=IPC_LOCK -p "127.0.0.1:${PORT}:8200" "$IMAGE" \
  server -dev -dev-root-token-id="$TOKEN" -dev-listen-address=0.0.0.0:8200 >/dev/null || { echo "FAIL: start vault"; exit 1; }
for _ in $(seq 1 30); do curl -sf "$ADDR/v1/sys/health" >/dev/null && break; sleep 1; done
curl -sf "$ADDR/v1/sys/health" >/dev/null || { echo "FAIL: vault never became healthy"; exit 1; }
echo "PASS: vault dev server answering on :${PORT}"
curl -sf -X POST -H "X-Vault-Token: $TOKEN" -d '{"type":"transit"}' "$ADDR/v1/sys/mounts/transit" >/dev/null \
  || { echo "FAIL: enable transit"; exit 1; }
echo "PASS: transit enabled"

export VAULT_ADDR="$ADDR" VAULT_TOKEN="$TOKEN" KK_LIVE_VAULT=1
cd "$REPO_ROOT" && go test ./tests/live/vault/ -count=1 -v 2>&1 | tee "$LOG"
rc=${PIPESTATUS[0]}
if [ "$rc" -ne 0 ]; then echo "FAIL: see above"; exit 1; fi
if grep -q -- '--- SKIP' "$LOG"; then echo "FAIL: a test was skipped"; exit 1; fi
echo "ALL CHECKS PASSED"
