#!/usr/bin/env bash
# W23-14: run the real CloudKMSStore GCP path against an in-repo Cloud KMS
# wire-format emulator (Google ships no official one; see README.md). No
# container needed. Proves request/response shapes, NOT IAM, quotas or HSM.
set -u -o pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
PORT="${KK_GCPKMS_PORT:-9111}"
WORK="$(mktemp -d -t kk-gcpkms.XXXXXX)"
LOG="$WORK/test.log"
EMU_PID=""
cleanup() { [ -n "$EMU_PID" ] && kill "$EMU_PID" >/dev/null 2>&1; rm -rf "$WORK"; }
trap cleanup EXIT

cd "$REPO_ROOT" && go build -o "$WORK/emulator" ./tests/live/kms-gcp/emulator || { echo "FAIL: build emulator"; exit 1; }
"$WORK/emulator" -addr "127.0.0.1:${PORT}" >"$WORK/emulator.log" 2>&1 &
EMU_PID=$!
for _ in $(seq 1 30); do curl -sf "http://127.0.0.1:${PORT}/healthz" >/dev/null && break; sleep 0.2; done
curl -sf "http://127.0.0.1:${PORT}/healthz" >/dev/null || { echo "FAIL: emulator never answered"; exit 1; }
echo "PASS: emulator answering on :${PORT}"

# Throwaway placeholders; the emulator only checks a bearer token is present.
export KRYPTKEEPER_GCP_KMS_ENDPOINT="http://127.0.0.1:${PORT}/v1" GOOGLE_ACCESS_TOKEN=kk-uat \
  KRYPTKEEPER_GCP_PROJECT=kk-uat KRYPTKEEPER_GCP_KEYRING=kk-uat KRYPTKEEPER_GCP_LOCATION=global \
  KRYPTKEEPER_GCP_KMS_PROTECTION=software KK_LIVE_KMS_GCP=1
go test ./tests/live/kms-gcp/ -count=1 -v 2>&1 | tee "$LOG"
rc=${PIPESTATUS[0]}
if [ "$rc" -ne 0 ]; then echo "FAIL: see above"; exit 1; fi
if grep -q -- '--- SKIP' "$LOG"; then echo "FAIL: a test was skipped"; exit 1; fi
echo "ALL CHECKS PASSED"
