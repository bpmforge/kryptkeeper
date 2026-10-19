#!/usr/bin/env bash
set -euo pipefail

# filename: scripts/test/run.sh
# Top-level P0 test harness runner.
#
# Design goals:
# - Non-zero exit for real suite failures.
# - Missing requested suites must fail closed.
# - Stable CI entry point: keep workflow callsite constant over time.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

declare -a suites=()

usage() {
  cat <<'USAGE'
Usage:
  scripts/test/run.sh [--suite <protocol|integration|smoke|tenant-idor>]...

Examples:
  scripts/test/run.sh
  scripts/test/run.sh --suite protocol --suite smoke
  scripts/test/run.sh --suite tenant-idor   # opt-in; not in the default set
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --suite)
      shift
      if [[ $# -eq 0 ]]; then
        echo "ERROR: --suite requires a value" >&2
        usage
        exit 2
      fi
      suites+=("$1")
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: unknown argument '$1'" >&2
      usage
      exit 2
      ;;
  esac
  shift
done

if [[ ${#suites[@]} -eq 0 ]]; then
  suites=(protocol integration smoke)
fi

failures=0

for suite in "${suites[@]}"; do
  case "$suite" in
    tenant-idor) suite_script="$ROOT_DIR/tests/integration/tenant_idor/run.sh" ;;
    *) suite_script="$ROOT_DIR/tests/$suite/run.sh" ;;
  esac

  if [[ ! -f "$suite_script" ]]; then
    echo "[test-harness] FAIL suite '$suite' missing at ${suite_script#"$ROOT_DIR"/}" >&2
    failures=$((failures + 1))
    continue
  fi

  echo "[test-harness] START suite=$suite"
  if bash "$suite_script"; then
    echo "[test-harness] PASS suite=$suite"
  else
    rc=$?
    echo "[test-harness] FAIL suite=$suite exit_code=$rc" >&2
    failures=$((failures + 1))
  fi
done

if [[ "$failures" -gt 0 ]]; then
  echo "[test-harness] Completed with $failures failing suite(s)" >&2
  exit 1
fi

echo "[test-harness] Completed with no failing suites"
