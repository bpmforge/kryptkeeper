-- (Postgres)
-- Purpose: W24-38 migration framework. Each import apply is recorded as a
-- batch, and every template it created as an item, so the report can be
-- re-read and W24-39 can disable exactly what a batch made. Templates live in
-- a JSON file, so batch ownership has to be kept here. Timestamps stay
-- RFC3339 text like the neighbouring tables.
-- Depends on: none
-- Rollback pair: 000144_migration_batches.down.sql
CREATE TABLE IF NOT EXISTS migration_batches (
    id             TEXT PRIMARY KEY,
    source         TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'applied' CHECK (status IN ('applied', 'rolled_back')),
    created_by     TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    rolled_back_at TEXT NOT NULL DEFAULT '',
    rolled_back_by TEXT NOT NULL DEFAULT '',
    report_json    TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS migration_batch_items (
    batch_id     TEXT NOT NULL REFERENCES migration_batches(id),
    source_key   TEXT NOT NULL,
    template_id  TEXT NOT NULL,
    name         TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    owner_hint   TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL,
    disabled_at  TEXT NOT NULL DEFAULT '',
    keep_reason  TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (batch_id, source_key)
);
CREATE INDEX IF NOT EXISTS idx_migration_items_source_key ON migration_batch_items(source_key);
