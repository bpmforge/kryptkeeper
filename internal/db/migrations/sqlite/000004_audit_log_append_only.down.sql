-- Wave W4 rollback (SQLite)
-- Paired with: 000004_audit_log_append_only.up.sql

BEGIN;

DROP TRIGGER IF EXISTS trg_audit_log_no_delete;
DROP TRIGGER IF EXISTS trg_audit_log_no_update;

DROP INDEX IF EXISTS idx_audit_actor;
DROP INDEX IF EXISTS idx_audit_resource;
DROP INDEX IF EXISTS idx_audit_timestamp;

DROP TABLE IF EXISTS audit_log;

COMMIT;
