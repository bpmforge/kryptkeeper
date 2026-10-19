#!/usr/bin/env bash
set -euo pipefail

# filename: scripts/test/go-unit-sharded.sh
# Backend unit tests for CI (ci-pr unit-backend), with internal/bootstrap split
# across parallel processes.
#
# internal/bootstrap is one package of ~2000 serial tests (they use t.Setenv,
# so t.Parallel is not an option) and was the job's whole critical path: ~23
# min under -race on the shared runner while the next-slowest package takes ~4.
# Separate processes each get their own environment, so sharding by -run is
# safe where t.Parallel is not.
#
# Usage: scripts/test/go-unit-sharded.sh [shards]   (default 4)
# Extra go test flags come from GO_TEST_FLAGS (default: -race -timeout 30m).

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

SHARDS="${1:-4}"
FLAGS="${GO_TEST_FLAGS:--race -timeout 30m}"
BOOT=./internal/bootstrap
LOG_DIR="$(mktemp -d)"
trap 'rm -rf "$LOG_DIR"' EXIT

# shellcheck disable=SC2086 # FLAGS is a deliberate word list.
# -list also compiles the race test binary once, so the shards hit the cache.
go test $FLAGS -list '^Test' "$BOOT" | grep '^Test' | sort > "$LOG_DIR/all.txt"
total=$(wc -l < "$LOG_DIR/all.txt" | tr -d ' ')
if [[ "$total" -eq 0 ]]; then
  echo "no tests listed in $BOOT" >&2
  exit 1
fi

# Spread the cores between the shards and the rest of the module.
cpus=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)
per_shard=$(( cpus / (SHARDS + 1) )); (( per_shard < 1 )) && per_shard=1

declare -a pids=() names=()
covered=0
for (( i = 0; i < SHARDS; i++ )); do
  awk -v n="$SHARDS" -v i="$i" '(NR - 1) % n == i' "$LOG_DIR/all.txt" > "$LOG_DIR/shard-$i.txt"
  count=$(wc -l < "$LOG_DIR/shard-$i.txt" | tr -d ' ')
  covered=$(( covered + count ))
  (( count == 0 )) && continue
  re="^($(paste -sd'|' "$LOG_DIR/shard-$i.txt"))\$"
  # shellcheck disable=SC2086
  GOMAXPROCS=$per_shard go test $FLAGS -count=1 -run "$re" "$BOOT" > "$LOG_DIR/shard-$i.log" 2>&1 &
  pids+=("$!"); names+=("bootstrap shard $((i + 1))/$SHARDS ($count tests)")
done

# A test must never silently fall between shards.
if (( covered != total )); then
  echo "shard split covered $covered of $total bootstrap tests" >&2
  exit 1
fi

# Everything else runs alongside the shards.
# shellcheck disable=SC2046,SC2086
go test $FLAGS $(go list ./... | grep -v '/internal/bootstrap$') > "$LOG_DIR/rest.log" 2>&1 &
pids+=("$!"); names+=("all other packages")

status=0
for k in "${!pids[@]}"; do
  if wait "${pids[$k]}"; then rc=0; else rc=$?; status=1; fi
  echo "::group::${names[$k]} (exit $rc)"
  if (( k < ${#pids[@]} - 1 )); then cat "$LOG_DIR/shard-$k.log"; else cat "$LOG_DIR/rest.log"; fi
  echo "::endgroup::"
done

# Failures again outside the collapsed groups, so they are easy to find.
if (( status != 0 )); then
  grep -h -E '^(--- FAIL|FAIL|panic:)' "$LOG_DIR"/*.log || true
fi
exit "$status"
