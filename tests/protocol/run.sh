#!/usr/bin/env bash
set -euo pipefail

# filename: tests/protocol/run.sh
# P0 concrete checks available today:
# - migration SQL up/down pair integrity
# - migration naming/order integrity

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

check_migration_dir() {
  local migration_dir="$1"
  local db_name="$2"
  local failures=0

  if [[ ! -d "$migration_dir" ]]; then
    echo "[protocol] WARN migration directory missing for ${db_name}: ${migration_dir}; skipping"
    return 0
  fi

  shopt -s nullglob
  local up_files=("$migration_dir"/*.up.sql)
  local down_files=("$migration_dir"/*.down.sql)

  if [[ ${#up_files[@]} -eq 0 && ${#down_files[@]} -eq 0 ]]; then
    echo "[protocol] WARN no migration files for ${db_name}; skipping"
    shopt -u nullglob
    return 0
  fi

  if [[ ${#up_files[@]} -eq 0 || ${#down_files[@]} -eq 0 ]]; then
    echo "[protocol] ERROR ${db_name}: missing .up.sql or .down.sql set"
    shopt -u nullglob
    return 1
  fi

  # Duplicate detection below relies on up_files being in ascending version
  # order (default bash glob sort) so a duplicate version's two filenames are
  # always adjacent -- true because every valid basename starts with a
  # zero-padded 6-digit version, which sorts identically as a string and as a
  # number. Deliberately no associative array here: this script targets
  # /bin/bash, and macOS ships bash 3.2 (no `local -A`), unlike the bash 5
  # on PATH in a typical dev shell or in CI's ubuntu runner.
  local previous_version=0 previous_base=""
  local up_file down_file base version_str version_num

  for up_file in "${up_files[@]}"; do
    base="$(basename "$up_file" .up.sql)"
    down_file="$migration_dir/${base}.down.sql"

    if [[ ! "$base" =~ ^[0-9]{6}_[a-z0-9_]+$ ]]; then
      echo "[protocol] ERROR ${db_name}: invalid migration filename '${base}.up.sql'"
      failures=$((failures + 1))
      continue
    fi

    if [[ ! -f "$down_file" ]]; then
      echo "[protocol] ERROR ${db_name}: missing down pair for '${base}.up.sql'"
      failures=$((failures + 1))
    fi

    version_str="${base%%_*}"
    version_num=$((10#${version_str}))

    # Versions are gap-tolerant, not contiguity-strict: the board pre-assigns
    # a version to each ticket at filing time, but tickets land out of
    # numeric order, so a gap is expected. loadMigrations()
    # (internal/db/migrate.go) keys migrations by map[int]migrationFile and
    # applies them in sorted numeric order regardless of gaps, so a gap is
    # provably harmless to the runner. A DUPLICATE version is not harmless --
    # it silently overwrites one migration's schema_migrations row with
    # another's -- so it stays a hard error. See CLAUDE.md "Migration version
    # numbers".
    if (( version_num == previous_version )); then
      echo "[protocol] ERROR ${db_name}: duplicate migration version ${version_str} (${base} collides with ${previous_base})"
      failures=$((failures + 1))
    fi
    previous_version=$version_num
    previous_base="$base"
  done

  for down_file in "${down_files[@]}"; do
    base="$(basename "$down_file" .down.sql)"
    if [[ ! -f "$migration_dir/${base}.up.sql" ]]; then
      echo "[protocol] ERROR ${db_name}: missing up pair for '${base}.down.sql'"
      failures=$((failures + 1))
    fi
  done

  shopt -u nullglob

  if (( failures > 0 )); then
    echo "[protocol] ERROR ${db_name}: migration integrity check failed (${failures} issue(s))"
    return 1
  fi

  echo "[protocol] PASS ${db_name}: migration pair + naming order integrity"
  return 0
}

echo "[protocol] Running migration SQL integrity checks"

protocol_failures=0

if ! check_migration_dir "$ROOT_DIR/internal/db/migrations/sqlite" "sqlite"; then
  protocol_failures=$((protocol_failures + 1))
fi

if ! check_migration_dir "$ROOT_DIR/internal/db/migrations/postgres" "postgres"; then
  protocol_failures=$((protocol_failures + 1))
fi

if (( protocol_failures > 0 )); then
  echo "[protocol] Completed with ${protocol_failures} failing check group(s)" >&2
  exit 1
fi

echo "[protocol] Completed with no failing checks"
