#!/usr/bin/env bash
set -euo pipefail

# Offline fixture test for scripts/check-licenses.sh (W25-21). Every case feeds canned
# go-licenses CSV / lockfile input through the script's override flags, so no network
# or go-licenses run is needed. CI runs this before the real gate so a regression in the
# checker itself fails the build.

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/check-licenses.sh"
FX="$HERE/testdata/licenses"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

FAILED=0
# expect <name> <want-exit> <want-stderr-substring|-> -- <args...>
expect() {
  local name="$1" want="$2" needle="$3"; shift 4
  local rc=0
  bash "$SCRIPT" "$@" > "$WORK/out" 2> "$WORK/err" || rc=$?
  if [[ "$rc" != "$want" ]]; then
    echo "FAIL $name: exit $rc, want $want"; cat "$WORK/err"; FAILED=1; return
  fi
  if [[ "$needle" != "-" ]] && ! grep -qF -- "$needle" "$WORK/err" "$WORK/out"; then
    echo "FAIL $name: output does not mention '$needle'"; cat "$WORK/err"; FAILED=1; return
  fi
  echo "PASS $name"
}

expect seeded_gpl_go_fails 1 example.com/gpl-lib -- check --go-csv "$FX/go-gpl.csv" --skip-npm
expect seeded_gpl_npm_fails 1 gpl-pkg -- check --skip-go --npm-lock "$FX/npm-gpl.json"
expect dual_license_or_passes 0 - -- check --skip-go --npm-lock "$FX/npm-or.json"
expect dual_license_and_fails 1 both -- check --skip-go --npm-lock "$FX/npm-and.json"
expect unknown_license_go_fails 1 example.com/mystery-lib -- check --go-csv "$FX/go-unknown.csv" --skip-npm
expect unknown_license_npm_fails 1 nolic -- check --skip-go --npm-lock "$FX/npm-unknown.json"
expect clean_fixture_passes 0 - -- check --go-csv "$FX/go-clean.csv" --npm-lock "$FX/npm-clean.json"

# Inventory completeness: generate from fixtures, then drop one row of each section.
INV="$WORK/inventory.md"
GEN=(--go-csv "$FX/go-clean.csv" --go-modules "$FX/go-modules.txt" --npm-lock "$FX/npm-clean.json" --inventory "$INV")
expect generate_fixture_inventory 0 - -- generate "${GEN[@]}"
expect count_check_passes_when_complete 0 "go: 2/2 npm: 2/2" -- verify-count "${GEN[@]}"
grep -v '^| example.com/other ' "$INV" > "$WORK/missing-go.md"
expect count_check_detects_missing_go_row 1 "go: 1/2" -- verify-count "${GEN[@]/$INV/$WORK/missing-go.md}"
grep -v '^| b | ' "$INV" > "$WORK/missing-npm.md"
expect count_check_detects_missing_npm_row 1 "npm: 1/2" -- verify-count "${GEN[@]/$INV/$WORK/missing-npm.md}"

# A denied licence must stop generate before it writes an inventory that hides it.
expect generate_refuses_denied 1 example.com/gpl-lib -- generate --go-csv "$FX/go-gpl.csv" --go-modules "$FX/go-modules.txt" --skip-npm --inventory "$WORK/never.md"
if [[ -e "$WORK/never.md" ]]; then echo "FAIL generate_refuses_denied: wrote inventory"; FAILED=1; fi

[[ "$FAILED" == 0 ]] || exit 1
echo "ALL PASS"
