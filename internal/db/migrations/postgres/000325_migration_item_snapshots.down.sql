-- (Postgres)
-- Rollback for 000325: removes the recorded pre-update template snapshots.
DROP INDEX IF EXISTS idx_migration_items_template_id;
DROP TABLE IF EXISTS migration_item_snapshots;
