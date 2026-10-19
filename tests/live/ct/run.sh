#!/usr/bin/env bash
# W24-22: gated live CT test (crt.sh) for a domain you control. Never run in CI.
# KK_LIVE_CT=1 KK_LIVE_CT_DOMAIN=<domain> bash tests/live/ct/run.sh
set -u -o pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
RESULT_FILE="${KK_CT_RESULT_FILE:-$HERE/last-run.md}"

if [ -z "${KK_LIVE_CT_DOMAIN:-}" ]; then
  echo "FAIL: KK_LIVE_CT_DOMAIN is empty. Set it to a domain you control that has a certificate issued by a CA that is not this hub (see tests/live/ct/README.md)."
  exit 2
fi
command -v go >/dev/null 2>&1 || { echo "FAIL: go is required"; exit 2; }
export KK_LIVE_CT=1

cd "$REPO_ROOT" && go test ./tests/live/ct/ -run TestCTLive -count=1 -v -timeout "${KK_CT_GO_TIMEOUT:-60m}" 2>&1 | tee "$RESULT_FILE"
rc=${PIPESTATUS[0]}
if [ "$rc" -eq 0 ]; then echo "ALL CHECKS PASSED (result block in $RESULT_FILE)"; else echo "FAIL: see above"; exit 1; fi
