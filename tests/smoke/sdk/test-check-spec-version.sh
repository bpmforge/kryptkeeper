#!/usr/bin/env bash
# W32-03: mismatch fixtures for scripts/check-spec-version.sh.
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CHECK="$ROOT_DIR/scripts/check-spec-version.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

printf 'openapi: 3.1.0\ninfo:\n  title: t\n  version: "1.2.3"\n' > "$TMP/a.yaml"
printf 'openapi: 3.1.0\ninfo:\n  title: t\n' > "$TMP/noversion.yaml"

FAILED=0
expect() { # name want(zero|nonzero) args...
  local name="$1" want="$2"; shift 2
  local rc=0
  bash "$CHECK" "$@" >/dev/null 2>&1 || rc=$?
  if { [ "$want" = zero ] && [ "$rc" -eq 0 ]; } || { [ "$want" = nonzero ] && [ "$rc" -ne 0 ]; }; then
    echo "[test-spec-version] PASS $name (exit $rc)"
  else
    echo "[test-spec-version] FAIL $name (exit $rc, wanted $want)"
    FAILED=1
  fi
}

expect "v1.2.3 equals spec 1.2.3"      zero    v1.2.3 "$TMP/a.yaml"
expect "v1.2.4 differs from spec"      nonzero v1.2.4 "$TMP/a.yaml"
expect "1.2.3 without v equals spec"   zero    1.2.3 "$TMP/a.yaml"
expect "missing spec file"             nonzero v1.2.3 "$TMP/does-not-exist.yaml"
expect "spec without version"          nonzero v1.2.3 "$TMP/noversion.yaml"
expect "empty tag"                     nonzero ""

exit "$FAILED"
