-- (PostgreSQL)
-- Rollback pair: 000087_audit_log_archive_delete.up.sql
-- Restores the strict function: every UPDATE and DELETE raises.
CREATE OR REPLACE FUNCTION prevent_audit_log_mutation()
RETURNS trigger AS $f$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only';
END;
$f$ LANGUAGE plpgsql;
