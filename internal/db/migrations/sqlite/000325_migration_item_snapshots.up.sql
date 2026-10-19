-- (SQLite)
-- Purpose: S-05. An import update records the template's prior state per batch
-- item so rolling the batch back restores it instead of disabling it. Kept in
-- its own table (rows exist only for updated items) so the store's
-- self-created schema can add it with CREATE TABLE IF NOT EXISTS; template_id
-- is indexed so planning can prove a template was made by a migration.
-- Depends on: 000144_migration_batches
-- Rollback pair: 000325_migration_item_snapshots.down.sql
CREATE TABLE IF NOT EXISTS migration_item_snapshots (
    batch_id   TEXT NOT NULL,
    source_key TEXT NOT NULL,
    prior_json TEXT NOT NULL,
    PRIMARY KEY (batch_id, source_key),
    FOREIGN KEY (batch_id, source_key) REFERENCES migration_batch_items(batch_id, source_key)
);
CREATE INDEX IF NOT EXISTS idx_migration_items_template_id ON migration_batch_items(template_id);
