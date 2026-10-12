-- Wave W4 rollback (PostgreSQL)
-- Paired with: 000004_audit_log_append_only.up.sql

BEGIN;

DROP POLICY IF EXISTS audit_insert_only ON audit_log;
DROP TRIGGER IF EXISTS trg_audit_log_append_only ON audit_log;

DROP INDEX IF EXISTS idx_audit_actor;
DROP INDEX IF EXISTS idx_audit_resource;
DROP INDEX IF EXISTS idx_audit_timestamp;

DO $$
DECLARE
    p RECORD;
BEGIN
    FOR p IN
        SELECT inhrelid::regclass AS child
          FROM pg_inherits
         WHERE inhparent = 'audit_log'::regclass
    LOOP
        EXECUTE format('DROP TABLE IF EXISTS %s', p.child);
    END LOOP;
END $$;

DROP TABLE IF EXISTS audit_log;
DROP FUNCTION IF EXISTS prevent_audit_log_mutation();

COMMIT;
