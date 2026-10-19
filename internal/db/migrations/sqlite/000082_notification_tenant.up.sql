-- Wave W22 (SQLite)
-- Purpose: tenant ownership for notification rules and silences (L-10). '' = legacy row, treated as the default tenant.
-- Rollback pair: 000082_notification_tenant.down.sql

ALTER TABLE notification_rules ADD COLUMN tenant TEXT NOT NULL DEFAULT '';

-- notification_silences was only ever created by inline self-heal DDL; create it
-- here (with tenant) so the migration is self-sufficient. A pre-existing table
-- without the column is upgraded by the store's EnsureSchema.
CREATE TABLE IF NOT EXISTS notification_silences (
    id          TEXT PRIMARY KEY,
    target_type TEXT NOT NULL
                 CHECK (target_type IN ('certificate', 'ca', 'template')),
    target_id   TEXT NOT NULL,
    created_by  TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    tenant      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_notification_silences_target ON notification_silences(target_type, target_id);
