#!/usr/bin/env bash
set -euo pipefail

# Back up a Kryptkeeper instance: the Postgres database plus every CA/key in
# the keystore, encrypted under a backup passphrase. Pair with restore.sh.
# See docs/ops/DR_RUNBOOK.md for the full recovery procedure.
#
# Usage:
#   scripts/deploy/backup.sh <out_dir>
#
# Required env:
#   DATABASE_URL         - postgres connection string for pg_dump
#   KRYPTKEEPER_API       - hub base URL, e.g. https://kryptkeeper.example.com
#   API_TOKEN             - a bearer token for a pki-admin principal
#   BACKUP_PASSPHRASE      - passphrase to encrypt exported keys under (NOT the
#                            keystore's own store passphrase — a separate
#                            secret, per keystore.ExportEncryptedKey's design)
#
# Output (in <out_dir>):
#   db-<timestamp>.sql.gz     - pg_dump of DATABASE_URL, gzipped
#   keys-<timestamp>.json     - keystore.Bundle from POST /api/v1/admin/backup
#   manifest.json              - {db_dump, keys_bundle, schema_version, created_at}
#   SHA256SUMS                 - checksums of the two artifacts above

OUT_DIR="${1:-}"
if [[ -z "$OUT_DIR" ]]; then
  echo "Usage: $0 <out_dir>" >&2
  exit 2
fi
mkdir -p "$OUT_DIR"

: "${DATABASE_URL:?DATABASE_URL is required}"
: "${KRYPTKEEPER_API:?KRYPTKEEPER_API is required}"
: "${API_TOKEN:?API_TOKEN is required}"
: "${BACKUP_PASSPHRASE:?BACKUP_PASSPHRASE is required}"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
DB_DUMP="db-${TS}.sql.gz"
KEYS_BUNDLE="keys-${TS}.json"

echo "[backup] dumping database..."
pg_dump "$DATABASE_URL" | gzip > "$OUT_DIR/$DB_DUMP"
echo "[backup] database dump written: $OUT_DIR/$DB_DUMP ($(du -h "$OUT_DIR/$DB_DUMP" | cut -f1))"

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

cat > "$OUT_DIR/manifest.json" <<EOF
{
  "schema_version": 1,
  "created_at": "$TS",
  "db_dump": "$DB_DUMP",
  "keys_bundle": "$KEYS_BUNDLE"
}
EOF

( cd "$OUT_DIR" && sha256sum "$DB_DUMP" "$KEYS_BUNDLE" manifest.json > SHA256SUMS )
echo "[backup] manifest + checksums written: $OUT_DIR/manifest.json, $OUT_DIR/SHA256SUMS"
echo "[backup] done"
