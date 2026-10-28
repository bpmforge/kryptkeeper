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
#        scripts/test/go-unit-sharded.sh --shard I/N   (bootstrap shard I of N only)
#        scripts/test/go-unit-sharded.sh --rest        (every package but bootstrap)
# The first form runs all shards and the rest as parallel processes on one
# machine. The --shard/--rest forms are for a CI job matrix: a 4-vCPU hosted
# runner gives each of five local processes about one core, so under -race
# bootstrap needs separate runners to finish in time (ci-main unit-race).
# Every shard I in 1..N must run somewhere for full coverage; the split is the
# same deterministic round-robin over the sorted test list in every mode.
# Extra go test flags come from GO_TEST_FLAGS (default: -race -timeout 30m).

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

FLAGS="${GO_TEST_FLAGS:--race -timeout 30m}"
BOOT=./internal/bootstrap

if [[ "${1:-}" == "--rest" ]]; then
  # shellcheck disable=SC2046,SC2086
  exec go test $FLAGS $(go list ./... | grep -v '/internal/bootstrap$')
fi

ONLY=""
if [[ "${1:-}" == "--shard" ]]; then
  if [[ ! "${2:-}" =~ ^([0-9]+)/([0-9]+)$ ]] || (( BASH_REMATCH[1] < 1 || BASH_REMATCH[1] > BASH_REMATCH[2] )); then
    echo "usage: $0 --shard I/N with 1 <= I <= N" >&2
    exit 2
  fi
  ONLY=$(( BASH_REMATCH[1] - 1 ))
  SHARDS=${BASH_REMATCH[2]}
else
  SHARDS="${1:-4}"
fi
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

if [[ -n "$ONLY" ]]; then
  awk -v n="$SHARDS" -v i="$ONLY" '(NR - 1) % n == i' "$LOG_DIR/all.txt" > "$LOG_DIR/shard.txt"
  count=$(wc -l < "$LOG_DIR/shard.txt" | tr -d ' ')
  echo "bootstrap shard $((ONLY + 1))/$SHARDS: $count of $total tests"
  (( count == 0 )) && exit 0
  re="^($(paste -sd'|' "$LOG_DIR/shard.txt"))\$"
  # shellcheck disable=SC2086
  go test $FLAGS -count=1 -run "$re" "$BOOT"
  exit $?
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
