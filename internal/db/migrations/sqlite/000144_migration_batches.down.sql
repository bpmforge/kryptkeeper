-- (SQLite)
-- Rollback for 000144: drops every recorded migration batch and its items.
DROP INDEX IF EXISTS idx_migration_items_source_key;
DROP TABLE IF EXISTS migration_batch_items;
DROP TABLE IF EXISTS migration_batches;
