#!/usr/bin/env bash
set -euo pipefail

# Round-trip test for backup.sh / restore.sh in SQLite mode. Needs only
# sqlite3, jq and gzip: BACKUP_DB_ONLY=1 keeps it independent of a running hub.
# Usage: bash scripts/deploy/backup_sqlite_test.sh

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

FAILED=0
fail() { echo "FAIL $*" >&2; FAILED=1; }

SRC="$TMP/src.db"
sqlite3 "$SRC" <<'SQL'
PRAGMA journal_mode=WAL;
CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, dirty INTEGER NOT NULL DEFAULT 0);
INSERT INTO schema_migrations (version) VALUES (1),(2),(20);
CREATE TABLE cas (id INTEGER PRIMARY KEY, name TEXT NOT NULL);
INSERT INTO cas (name) VALUES ('root'),('issuing');
CREATE TABLE certificates (id INTEGER PRIMARY KEY, cn TEXT, payload BLOB);
WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 1000)
  INSERT INTO certificates (cn, payload) SELECT 'host-' || i, randomblob(64) FROM n;
CREATE TABLE audit_events (id INTEGER PRIMARY KEY, msg TEXT);
INSERT INTO audit_events (msg) VALUES ('a'),('b'),('c');
CREATE TABLE empty_table (id INTEGER PRIMARY KEY, note TEXT);
SQL

export KRYPTKEEPER_DB_MODE=sqlite BACKUP_DB_ONLY=1
OUT="$TMP/out"
SQLITE_DB_PATH="$SRC" bash "$HERE/backup.sh" "$OUT"

DEST="$TMP/restored/kryptkeeper.db"
SQLITE_DB_PATH="$DEST" bash "$HERE/restore.sh" "$OUT"

[[ "$(sqlite3 "$DEST" 'PRAGMA integrity_check;')" == "ok" ]] || fail "restored integrity_check"
[[ "$(jq -r .db_engine "$OUT/manifest.json")" == "sqlite" ]] || fail "manifest db_engine"
[[ "$(jq -r .db_schema_version "$OUT/manifest.json")" == "20" ]] || fail "manifest db_schema_version"

TABLES="$(sqlite3 "$SRC" "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name;")"
[[ "$(echo "$TABLES" | wc -l | tr -d ' ')" -ge 5 ]] || fail "fewer than 5 tables"
for t in $TABLES; do
  a="$(sqlite3 "$SRC" "SELECT COUNT(*) FROM \"$t\";")"
  b="$(sqlite3 "$DEST" "SELECT COUNT(*) FROM \"$t\";")"
  if [[ "$a" == "$b" ]]; then echo "PASS table=$t rows=$a"; else fail "table=$t source=$a restored=$b"; fi
done

# Non-empty target must be refused without --force, and left untouched.
BEFORE="$(shasum -a 256 "$DEST" | cut -d' ' -f1)"
set +e
SQLITE_DB_PATH="$DEST" bash "$HERE/restore.sh" "$OUT" >/dev/null 2>&1
rc=$?
set -e
if [[ "$rc" == "3" ]]; then echo "PASS refuses non-empty target (exit 3)"; else fail "expected exit 3 without --force, got $rc"; fi
[[ "$(shasum -a 256 "$DEST" | cut -d' ' -f1)" == "$BEFORE" ]] || fail "target changed after refused restore"

# One flipped byte must fail the checksum and leave the target alone.
TAMPER="$TMP/tampered"
cp -R "$OUT" "$TAMPER"
GZ="$(ls "$TAMPER"/db-*.sqlite.gz)"
printf '\xff' | dd of="$GZ" bs=1 seek=20 count=1 conv=notrunc 2>/dev/null
set +e
SQLITE_DB_PATH="$DEST" bash "$HERE/restore.sh" --force "$TAMPER" >/dev/null 2>&1
rc=$?
set -e
if [[ "$rc" != "0" ]]; then echo "PASS tampered backup rejected (exit $rc)"; else fail "tampered backup was accepted"; fi
[[ "$(shasum -a 256 "$DEST" | cut -d' ' -f1)" == "$BEFORE" ]] || fail "target changed after tampered restore"
ls "$DEST".pre-restore-* >/dev/null 2>&1 && fail "tampered restore moved the target aside"

# --force replaces the target and keeps the old one.
SQLITE_DB_PATH="$DEST" bash "$HERE/restore.sh" --force "$OUT" >/dev/null
if ls "$DEST".pre-restore-* >/dev/null 2>&1; then echo "PASS --force kept .pre-restore file"; else fail "no .pre-restore file after --force"; fi
[[ "$(sqlite3 "$DEST" 'SELECT COUNT(*) FROM certificates;')" == "1000" ]] || fail "rows after --force restore"

# A postgres-mode restore of a sqlite backup is a config mistake, not a restore.
set +e
KRYPTKEEPER_DB_MODE=postgres DATABASE_URL=x bash "$HERE/restore.sh" "$OUT" >/dev/null 2>&1
rc=$?
set -e
if [[ "$rc" == "2" ]]; then echo "PASS engine mismatch rejected (exit 2)"; else fail "expected exit 2 on engine mismatch, got $rc"; fi

if [[ "$FAILED" != "0" ]]; then exit 1; fi
echo "ALL PASS"
