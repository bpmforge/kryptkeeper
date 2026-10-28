#!/usr/bin/env bash
# `make gate`: the checks a change needs, chosen from the areas it touches
# (scripts/ci/changed-areas.sh, against the merge base with origin/main).
# GATE_FULL=1 runs everything; a change to CI, scripts or build config always does.
# GATE_BASE=<ref> compares against that ref instead of the merge base.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

if [ "${GATE_FULL:-}" = 1 ]; then
  areas=$(bash scripts/ci/changed-areas.sh "")
  areas=$(echo "$areas" | sed 's/=.*/=true/')
else
  areas=$(bash scripts/ci/changed-areas.sh "${GATE_BASE:-}")
fi
eval "$areas"
echo "gate: areas $(echo "$areas" | grep '=true' | cut -d= -f1 | tr '\n' ' ')"

ran=() skipped=()
step() { # name, condition, command...
  local name=$1 cond=$2; shift 2
  if [ "$cond" = true ]; then echo "gate: $name"; "$@"; ran+=("$name"); else skipped+=("$name"); fi
}
either() { for v in "$@"; do [ "$v" = true ] && { echo true; return; }; done; echo false; }

step "check-slop" true python3 scripts/ci/check-slop.py ${GATE_BASE:-}
step "go build" "$(either "$go" "$all")" go build ./...
step "go test" "$(either "$go" "$all")" go test ./...
step "make lint" "$(either "$go" "$all")" make lint
step "openapi" "$(either "$go" "$api" "$all")" bash scripts/validate-openapi.sh
step "protocol" "$(either "$go" "$all")" bash tests/protocol/run.sh
step "ui lint+test" "$(either "$ui" "$api" "$all")" bash -c 'cd ui && npm run lint && npm test -- --run'
step "site" "$(either "$site" "$docs" "$all")" bash -c 'node site/tools/build.mjs --check && node --test site/tools/*.test.mjs'

echo "gate: green (ran: ${ran[*]:-none}; skipped as unaffected: ${skipped[*]:-none})"
