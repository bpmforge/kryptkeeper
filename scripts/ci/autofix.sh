#!/usr/bin/env bash
# Rewrites safe, mechanical issues in changed files: gofmt -s on Go, eslint --fix
# on the UI. Anything that needs judgment is left to scripts/ci/check-slop.py.
#
# Usage: scripts/ci/autofix.sh            files changed on this branch (vs origin/main) and in the tree
#        scripts/ci/autofix.sh --staged   staged files; a fixed file is re-staged only
#                                         when it has no unstaged edits, so a partial
#                                         stage never pulls in unrelated work
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

if [ "${1:-}" = "--staged" ]; then
  staged=true
  files=$(git diff --cached --name-only --diff-filter=ACMR)
else
  staged=false
  base=$(git merge-base HEAD origin/main 2>/dev/null || echo HEAD)
  files=$( { git diff --name-only --diff-filter=ACMR "$base"...HEAD; git diff --name-only --diff-filter=ACMR; } | sort -u)
fi

go_files=() ui_files=()
while IFS= read -r f; do
  [ -n "$f" ] && [ -f "$f" ] || continue
  if $staged && ! git diff --quiet -- "$f"; then
    echo "autofix: skipping $f (it also has unstaged edits)"
    continue
  fi
  case "$f" in
    *.go) go_files+=("$f") ;;
    ui/src/*.ts|ui/src/*.tsx) case "$f" in ui/src/generated/*) ;; *) ui_files+=("${f#ui/}") ;; esac ;;
  esac
done <<< "$files"

fixed=()
if [ ${#go_files[@]} -gt 0 ]; then
  for f in $(gofmt -s -l "${go_files[@]}"); do gofmt -s -w "$f"; fixed+=("$f"); done
fi
if [ ${#ui_files[@]} -gt 0 ]; then
  if [ -d ui/node_modules ]; then
    before=$(cd ui && git diff --name-only -- "${ui_files[@]}")
    (cd ui && npx --no-install eslint --fix "${ui_files[@]}") || true
    for f in $(cd ui && git diff --name-only --relative -- "${ui_files[@]}"); do
      case " $before " in *" ui/$f "*) ;; *) fixed+=("ui/$f") ;; esac
    done
  else
    echo "autofix: ui/node_modules missing, skipping eslint --fix (run npm --prefix ui ci)"
  fi
fi

if [ ${#fixed[@]} -gt 0 ]; then
  echo "autofix: fixed ${fixed[*]}"
  if $staged; then git add -- "${fixed[@]}"; fi
else
  echo "autofix: nothing to fix"
fi
