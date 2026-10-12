#!/usr/bin/env bash
set -euo pipefail

# Restore a Kryptkeeper instance from a backup produced by backup.sh: the
# Postgres database, then every CA/key in the keystore.
#
# ORDERING IS LOAD-BEARING — do not boot any Kryptkeeper instance against
# DATABASE_URL before running this script. A default `pg_dump` replays full
# CREATE TABLE statements and seed-data COPY rows; if the hub has already
# booted against DATABASE_URL first, its own migration run (W10-01) has
# already created that schema, and this script's `psql` restore will abort
# on "relation already exists" the moment ON_ERROR_STOP hits the first
# collision. The correct order is: (1) provision a genuinely empty Postgres
# database — nothing has ever connected a Kryptkeeper hub to it — (2) run
# this script, which restores the dump into that empty DB first, (3) ONLY
# THEN boot a hub instance against DATABASE_URL — its migration run sees
# schema_migrations already fully populated (restored from the dump) and is
# a clean no-op, exactly like TestRunMigrations_SecondRunIsNoOp
# (internal/db/migrate_test.go) already proves for this exact shape — (4)
# this script polls /readyz and, once the hub you just booted responds,
# imports the keystore bundle. See docs/ops/DR_RUNBOOK.md.
#
# Usage:
#   scripts/deploy/restore.sh <backup_dir>
#
# Required env:
#   DATABASE_URL         - postgres connection string to restore INTO — MUST
#                           be a genuinely empty database (see ordering note
#                           above; do not point this at a DB a hub has ever
#                           booted against)
#   KRYPTKEEPER_API       - hub base URL to poll for readiness and import keys
#                           into. Boot this instance against DATABASE_URL
#                           only AFTER this script's "database restored"
#                           message — the script waits below for it.
#   API_TOKEN             - a bearer token for a pki-admin principal on that
#                           fresh instance
#   BACKUP_PASSPHRASE      - the same passphrase backup.sh encrypted keys under
#
# Fails closed: any step failing aborts the whole restore (set -e). Run
# scripts/deploy/smoke.sh against the restored instance afterward to verify.
#
# NOTE: this script's pg_dump/psql half has not been executed against a real
# Postgres server in the environment this was written in (no pg_dump/psql
# client available) — see docs/ops/DR_RUNBOOK.md's disclosed-gap section.

BACKUP_DIR="${1:-}"
if [[ -z "$BACKUP_DIR" ]]; then
  echo "Usage: $0 <backup_dir>" >&2
  exit 2
fi
if [[ ! -f "$BACKUP_DIR/manifest.json" ]]; then
  echo "ERROR: $BACKUP_DIR/manifest.json not found — not a backup.sh output directory" >&2
  exit 2
fi

: "${DATABASE_URL:?DATABASE_URL is required}"
: "${KRYPTKEEPER_API:?KRYPTKEEPER_API is required}"
: "${API_TOKEN:?API_TOKEN is required}"
: "${BACKUP_PASSPHRASE:?BACKUP_PASSPHRASE is required}"

echo "[restore] verifying checksums..."
( cd "$BACKUP_DIR" && sha256sum -c SHA256SUMS )

DB_DUMP=$(jq -r '.db_dump' "$BACKUP_DIR/manifest.json")
KEYS_BUNDLE=$(jq -r '.keys_bundle' "$BACKUP_DIR/manifest.json")
if [[ -z "$DB_DUMP" || -z "$KEYS_BUNDLE" ]]; then
  echo "ERROR: could not read db_dump/keys_bundle from $BACKUP_DIR/manifest.json" >&2
  exit 1
fi
if [[ ! -f "$BACKUP_DIR/$DB_DUMP" || ! -f "$BACKUP_DIR/$KEYS_BUNDLE" ]]; then
  echo "ERROR: manifest references files not present in $BACKUP_DIR" >&2
  exit 1
fi

echo "[restore] restoring database from $DB_DUMP into DATABASE_URL (this must be a database no hub has ever booted against)..."
gunzip -c "$BACKUP_DIR/$DB_DUMP" | psql "$DATABASE_URL" -v ON_ERROR_STOP=1
echo "[restore] database restored"
echo "[restore] >>> now boot a Kryptkeeper hub instance against DATABASE_URL if you have not already — its migration run will safely no-op against the just-restored schema_migrations table. <<<"

# This is an operator-supervised recovery, not an SLA path — the wait below
# is deliberately long (~15 minutes) rather than a tight timeout, since the
# database is ALREADY restored at this point: if this script exits without
# importing keys, re-running the whole script would replay psql onto a now
# non-empty database and abort on the first CREATE collision (by design,
# fail-closed — see the ordering note at the top of this file). The recovery
# instructions on timeout below tell the operator to finish the key import
# manually instead of re-running this script.
echo "[restore] waiting for $KRYPTKEEPER_API/readyz (boot the hub against DATABASE_URL now if you haven't)..."
READY=""
for i in $(seq 1 180); do
  if curl -ksS -o /dev/null -w "%{http_code}" --max-time 5 "$KRYPTKEEPER_API/readyz" | grep -q "^200$"; then
    READY="1"
    break
  fi
  if (( i % 15 == 0 )); then
    echo "[restore] still waiting for $KRYPTKEEPER_API/readyz ($((i * 5))s elapsed)..."
  fi
  sleep 5
done

import_keys() {
  local body
  body=$(mktemp)
  jq -n --arg pass "$BACKUP_PASSPHRASE" --slurpfile bundle "$BACKUP_DIR/$KEYS_BUNDLE" \
    '{backup_passphrase: $pass, bundle: $bundle[0]}' > "$body"

  local http_code
  http_code=$(curl -ksS -o /tmp/kryptkeeper_restore_response.json -w "%{http_code}" \
    -X POST "$KRYPTKEEPER_API/api/v1/admin/restore" \
    -H "Authorization: Bearer $API_TOKEN" \
    -H "Content-Type: application/json" \
    --data-binary "@$body")
  rm -f "$body"

  cat /tmp/kryptkeeper_restore_response.json
  echo
  if [[ "$http_code" != "200" ]]; then
    echo "ERROR: key restore returned HTTP $http_code (see response above) — a 207 means some keys imported and others didn't, inspect before proceeding" >&2
    return 1
  fi
  return 0
}

if [[ -z "$READY" ]]; then
  echo "ERROR: $KRYPTKEEPER_API/readyz did not return 200 after 15 minutes." >&2
  echo "" >&2
  echo "The database HAS ALREADY BEEN RESTORED — do NOT re-run this script (a second psql" >&2
  echo "replay will abort on the schema that's now already there). Once the hub is up and" >&2
  echo "/readyz returns 200, finish the key import yourself:" >&2
  echo "" >&2
  echo "  jq -n --arg pass \"\$BACKUP_PASSPHRASE\" --slurpfile bundle \"$BACKUP_DIR/$KEYS_BUNDLE\" \\" >&2
  echo "    '{backup_passphrase: \$pass, bundle: \$bundle[0]}' | \\" >&2
  echo "    curl -ksS -X POST \"\$KRYPTKEEPER_API/api/v1/admin/restore\" \\" >&2
  echo "    -H \"Authorization: Bearer \$API_TOKEN\" -H 'Content-Type: application/json' --data-binary @-" >&2
  exit 1
fi

echo "[restore] importing keystore bundle..."
if ! import_keys; then
  exit 1
fi

echo "[restore] done — run scripts/deploy/smoke.sh against $KRYPTKEEPER_API to verify"
