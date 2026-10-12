#!/usr/bin/env bash
set -euo pipefail

# filename: tests/integration/run.sh
# P0 concrete checks available today:
# - sqlite migration smoke apply/rollback for W1..W7 (if sqlite3 exists)
# - GitHub workflow YAML parse checks (if YAML parser exists)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

run_sqlite_migration_smoke() {
  local migration_dir="$ROOT_DIR/internal/db/migrations/sqlite"
  local failures=0
  local db_file

  if [[ ! -d "$migration_dir" ]]; then
    echo "[integration] WARN sqlite migration directory missing; skipping sqlite smoke"
    return 0
  fi

  if ! command -v sqlite3 >/dev/null 2>&1; then
    echo "[integration] WARN sqlite3 not installed; skipping sqlite migration smoke"
    return 0
  fi

  db_file="$(mktemp "${TMPDIR:-/tmp}/kryptkeeper-migrations-XXXXXX.db")"

  local week version up_candidates down_candidates up_file down_file
  shopt -s nullglob

  for week in 1 2 3 4 5 6 7; do
    version="$(printf "%06d" "$week")"
    up_candidates=("$migration_dir/${version}_"*.up.sql)
    down_candidates=("$migration_dir/${version}_"*.down.sql)

    if [[ ${#up_candidates[@]} -ne 1 ]]; then
      echo "[integration] ERROR sqlite W${week}: expected 1 up migration for version ${version}, found ${#up_candidates[@]}"
      failures=$((failures + 1))
      continue
    fi

    if [[ ${#down_candidates[@]} -ne 1 ]]; then
      echo "[integration] ERROR sqlite W${week}: expected 1 down migration for version ${version}, found ${#down_candidates[@]}"
      failures=$((failures + 1))
      continue
    fi

    up_file="${up_candidates[0]}"
    down_file="${down_candidates[0]}"

    if ! sqlite3 "$db_file" < "$up_file"; then
      echo "[integration] ERROR sqlite W${week}: failed applying $(basename "$up_file")"
      failures=$((failures + 1))
      continue
    fi

    echo "[integration] PASS sqlite W${week}: applied $(basename "$up_file")"
  done

  # Roll back in reverse order so down scripts are exercised too.
  for week in 7 6 5 4 3 2 1; do
    version="$(printf "%06d" "$week")"
    down_candidates=("$migration_dir/${version}_"*.down.sql)

    if [[ ${#down_candidates[@]} -ne 1 ]]; then
      echo "[integration] ERROR sqlite W${week}: expected 1 down migration for rollback"
      failures=$((failures + 1))
      continue
    fi

    down_file="${down_candidates[0]}"
    if ! sqlite3 "$db_file" < "$down_file"; then
      echo "[integration] ERROR sqlite W${week}: failed rollback $(basename "$down_file")"
      failures=$((failures + 1))
      continue
    fi

    echo "[integration] PASS sqlite W${week}: rolled back $(basename "$down_file")"
  done

  shopt -u nullglob

  local integrity_result
  integrity_result="$(sqlite3 "$db_file" "PRAGMA integrity_check;" || true)"
  if [[ "$integrity_result" != "ok" ]]; then
    echo "[integration] ERROR sqlite integrity_check failed after migration smoke"
    failures=$((failures + 1))
  fi

  rm -f "$db_file"

  if (( failures > 0 )); then
    echo "[integration] ERROR sqlite migration smoke failed (${failures} issue(s))"
    return 1
  fi

  echo "[integration] PASS sqlite migration smoke W1..W7"
  return 0
}

run_workflow_yaml_parse_check() {
  local workflow_dir="$ROOT_DIR/.github/workflows"
  local failures=0
  local parser=""

  if [[ ! -d "$workflow_dir" ]]; then
    echo "[integration] WARN .github/workflows not found; skipping YAML parse check"
    return 0
  fi

  shopt -s nullglob
  local workflow_files=("$workflow_dir"/*.yml "$workflow_dir"/*.yaml)
  shopt -u nullglob

  if [[ ${#workflow_files[@]} -eq 0 ]]; then
    echo "[integration] WARN no workflow YAML files found; skipping YAML parse check"
    return 0
  fi

  if command -v ruby >/dev/null 2>&1; then
    parser="ruby"
  elif command -v python3 >/dev/null 2>&1 && python3 - <<'PY' >/dev/null 2>&1
import importlib.util
import sys
sys.exit(0 if importlib.util.find_spec("yaml") else 1)
PY
  then
    parser="python"
  else
    echo "[integration] WARN no YAML parser available (ruby or python3+PyYAML); skipping workflow parse check"
    return 0
  fi

  local workflow_file
  for workflow_file in "${workflow_files[@]}"; do
    if [[ "$parser" == "ruby" ]]; then
      if ! ruby -e 'require "yaml"; YAML.load_file(ARGV[0])' "$workflow_file" >/dev/null; then
        echo "[integration] ERROR workflow parse failed: $(basename "$workflow_file")"
        failures=$((failures + 1))
        continue
      fi
    else
      if ! python3 - "$workflow_file" <<'PY' >/dev/null
import sys
import yaml
with open(sys.argv[1], "r", encoding="utf-8") as f:
    yaml.safe_load(f)
PY
      then
        echo "[integration] ERROR workflow parse failed: $(basename "$workflow_file")"
        failures=$((failures + 1))
        continue
      fi
    fi

    echo "[integration] PASS workflow parse: $(basename "$workflow_file")"
  done

  if (( failures > 0 )); then
    echo "[integration] ERROR workflow YAML parse check failed (${failures} file(s))"
    return 1
  fi

  echo "[integration] PASS workflow YAML parse check"
  return 0
}

echo "[integration] Running concrete integration safety checks"

integration_failures=0

if ! run_sqlite_migration_smoke; then
  integration_failures=$((integration_failures + 1))
fi

if ! run_workflow_yaml_parse_check; then
  integration_failures=$((integration_failures + 1))
fi

if (( integration_failures > 0 )); then
  echo "[integration] Completed with ${integration_failures} failing check group(s)" >&2
  exit 1
fi

echo "[integration] Completed with no failing checks"
