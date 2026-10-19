#!/usr/bin/env bash
set -euo pipefail

# Back up a Kryptkeeper instance: the database (Postgres, or a SQLite file via
# the online .backup API) plus every CA/key in the keystore, encrypted under a
# backup passphrase. Pair with restore.sh.
# See docs/ops/DR_RUNBOOK.md for the full recovery procedure.
#
# Usage:
#   scripts/deploy/backup.sh <out_dir>
#
# Required env:
#   KRYPTKEEPER_DB_MODE   - "postgres" (default) or "sqlite"
#   DATABASE_URL         - postgres connection string for pg_dump (postgres only)
#   SQLITE_DB_PATH        - sqlite only, optional: plain file path (NOT a DSN);
#                            default ${KRYPTKEEPER_DATA_DIR:-./var}/kryptkeeper.db.
#                            The compose hub keeps it at /var/kryptkeeper/data in
#                            volume appdata and runs read_only, so run this via
#                            `docker compose exec` or from the host on the volume path.
#   KRYPTKEEPER_API       - hub base URL, e.g. https://kryptkeeper.example.com
#   API_TOKEN             - a bearer token for a pki-admin principal
#   BACKUP_PASSPHRASE      - passphrase to encrypt exported keys under (NOT the
#                            keystore's own store passphrase — a separate
#                            secret, per keystore.ExportEncryptedKey's design)
#
# Optional env:
#   BACKUP_DB_ONLY=1      - skip the key export (hub, API_TOKEN and
#                            BACKUP_PASSPHRASE not needed); keys_bundle is "".
#
# Output (in <out_dir>):
#   db-<timestamp>.sql.gz     - pg_dump of DATABASE_URL, gzipped (postgres)
#   db-<timestamp>.sqlite.gz  - consistent copy of the SQLite DB, gzipped (sqlite)
#   keys-<timestamp>.json     - keystore.Bundle from POST /api/v1/admin/backup
#   manifest.json              - {db_engine, db_dump, keys_bundle, schema_version, created_at}
#   SHA256SUMS                 - checksums of the artifacts above

# macOS ships shasum, not sha256sum.
sha256_sum() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }

DB_ENGINE="${KRYPTKEEPER_DB_MODE:-postgres}"
if [[ "$DB_ENGINE" != "postgres" && "$DB_ENGINE" != "sqlite" ]]; then
  echo "ERROR: KRYPTKEEPER_DB_MODE must be postgres or sqlite, got: $DB_ENGINE" >&2
  exit 2
fi
DB_ONLY="${BACKUP_DB_ONLY:-}"

OUT_DIR="${1:-}"
if [[ -z "$OUT_DIR" ]]; then
  echo "Usage: $0 <out_dir>" >&2
  exit 2
fi
mkdir -p "$OUT_DIR"

if [[ "$DB_ENGINE" == "postgres" ]]; then
  : "${DATABASE_URL:?DATABASE_URL is required}"
fi
if [[ -z "$DB_ONLY" ]]; then
  : "${KRYPTKEEPER_API:?KRYPTKEEPER_API is required}"
  : "${API_TOKEN:?API_TOKEN is required}"
  : "${BACKUP_PASSPHRASE:?BACKUP_PASSPHRASE is required}"
fi

TS="$(date -u +%Y%m%dT%H%M%SZ)"
KEYS_BUNDLE="keys-${TS}.json"
DB_SCHEMA_VERSION_JSON=""

if [[ "$DB_ENGINE" == "sqlite" ]]; then
  SQLITE_DB_PATH="${SQLITE_DB_PATH:-${KRYPTKEEPER_DATA_DIR:-./var}/kryptkeeper.db}"
  DB_DUMP="db-${TS}.sqlite.gz"
  command -v sqlite3 >/dev/null || { echo "ERROR: sqlite3 not found on PATH" >&2; exit 2; }
  if [[ ! -f "$SQLITE_DB_PATH" ]]; then
    echo "ERROR: SQLite database not found: $SQLITE_DB_PATH" >&2
    exit 2
  fi
  SQLITE_TMP="$(mktemp -d)"
  trap 'rm -rf "$SQLITE_TMP"' EXIT

  # .backup (not cp) because the hub runs in WAL mode: a plain file copy would
  # miss pages that only exist in the -wal file.
  echo "[backup] snapshotting sqlite database..."
  sqlite3 "$SQLITE_DB_PATH" ".timeout 10000" ".backup '$SQLITE_TMP/db.sqlite'"
  INTEGRITY="$(sqlite3 "$SQLITE_TMP/db.sqlite" "PRAGMA integrity_check;")"
  if [[ "$INTEGRITY" != "ok" ]]; then
    echo "[backup] FAIL: integrity_check on the snapshot returned: $INTEGRITY" >&2
    exit 1
  fi
  gzip -c "$SQLITE_TMP/db.sqlite" > "$OUT_DIR/$DB_DUMP"
  DB_SCHEMA_VERSION_JSON="$(sqlite3 "$SQLITE_TMP/db.sqlite" "SELECT COALESCE(MAX(version),0) FROM schema_migrations;")"
  echo "[backup] database snapshot written: $OUT_DIR/$DB_DUMP ($(du -h "$OUT_DIR/$DB_DUMP" | cut -f1))"
else
  DB_DUMP="db-${TS}.sql.gz"
  echo "[backup] dumping database..."
  pg_dump "$DATABASE_URL" | gzip > "$OUT_DIR/$DB_DUMP"
  echo "[backup] database dump written: $OUT_DIR/$DB_DUMP ($(du -h "$OUT_DIR/$DB_DUMP" | cut -f1))"
fi

if [[ -n "$DB_ONLY" ]]; then
  echo "[backup] BACKUP_DB_ONLY set: skipping keystore export"
  KEYS_BUNDLE=""
else
  echo "[backup] exporting keystore..."
  HTTP_CODE=$(curl -ksS -o "$OUT_DIR/$KEYS_BUNDLE" -w "%{http_code}" \
    -X POST "$KRYPTKEEPER_API/api/v1/admin/backup" \
    -H "Authorization: Bearer $API_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"backup_passphrase\":\"$BACKUP_PASSPHRASE\"}")
  if [[ "$HTTP_CODE" != "200" ]]; then
    echo "[backup] FAIL: key export returned HTTP $HTTP_CODE" >&2
    cat "$OUT_DIR/$KEYS_BUNDLE" >&2 || true
    exit 1
  fi

  # Surface non-exported keys (HSM/KMS/Vault-backed, or a genuine per-key
  # error) loudly — a silent bundle would look complete but isn't.
  SKIPPED=$(jq '[.keys[] | select(.status == "skipped_non_extractable")] | length' "$OUT_DIR/$KEYS_BUNDLE")
  ERRORED=$(jq '[.keys[] | select(.status == "error")] | length' "$OUT_DIR/$KEYS_BUNDLE")
  EXPORTED=$(jq '[.keys[] | select(.status == "exported")] | length' "$OUT_DIR/$KEYS_BUNDLE")
  echo "[backup] keystore bundle written: $OUT_DIR/$KEYS_BUNDLE (exported=$EXPORTED skipped_non_extractable=$SKIPPED error=$ERRORED)"
  if [[ "$SKIPPED" != "0" ]]; then
    echo "[backup] WARNING: $SKIPPED key(s) are on a non-extractable backend (HSM/KMS/Vault) and were NOT included in this bundle." >&2
    echo "[backup]          Those keys stay in their HSM/KMS; back up the DB (which records the key reference) and rely on the HSM/KMS's own DR procedure for the key material itself." >&2
  fi
  if [[ "$ERRORED" != "0" ]]; then
    echo "[backup] ERROR: $ERRORED key(s) failed to export for an unexpected reason — inspect $OUT_DIR/$KEYS_BUNDLE before relying on this backup." >&2
    exit 1
  fi
fi

SCHEMA_LINE=""
[[ -n "$DB_SCHEMA_VERSION_JSON" ]] && SCHEMA_LINE=$'\n  "db_schema_version": '"$DB_SCHEMA_VERSION_JSON"','
cat > "$OUT_DIR/manifest.json" <<EOF
{
  "schema_version": 1,
  "db_engine": "$DB_ENGINE",$SCHEMA_LINE
  "created_at": "$TS",
  "db_dump": "$DB_DUMP",
  "keys_bundle": "$KEYS_BUNDLE"
}
EOF

SUM_FILES=("$DB_DUMP" manifest.json)
[[ -n "$KEYS_BUNDLE" ]] && SUM_FILES=("$DB_DUMP" "$KEYS_BUNDLE" manifest.json)
( cd "$OUT_DIR" && sha256_sum "${SUM_FILES[@]}" > SHA256SUMS )
echo "[backup] manifest + checksums written: $OUT_DIR/manifest.json, $OUT_DIR/SHA256SUMS"
echo "[backup] done"
