-- (Postgres)
-- Purpose: R-05. An import update retires the item it supersedes; this records
-- the link per batch item so rolling the update back can reactivate that item
-- and the restored template is owned by a batch again. Own table so the
-- store's self-created schema can add it with CREATE TABLE IF NOT EXISTS.
-- Depends on: 000144_migration_batches
-- Rollback pair: 000326_migration_item_supersedes.down.sql
CREATE TABLE IF NOT EXISTS migration_item_supersedes (
    batch_id            TEXT NOT NULL,
    source_key          TEXT NOT NULL,
    supersedes_batch_id TEXT NOT NULL,
    PRIMARY KEY (batch_id, source_key),
    FOREIGN KEY (batch_id, source_key) REFERENCES migration_batch_items(batch_id, source_key)
);
