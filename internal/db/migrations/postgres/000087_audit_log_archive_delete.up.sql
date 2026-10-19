-- (PostgreSQL)
-- Purpose: W22-07. Let the audit archive job delete rows it has already
-- archived, and nothing else. audit_log stays append-only: UPDATE always
-- raises, and DELETE raises unless the transaction has set
-- kryptkeeper.audit_archive = 'on' (SET LOCAL, so it ends with the
-- transaction) AND an audit_archives row, written before the delete, covers
-- the row's id range and is later than its timestamp. The second condition
-- makes "checkpoint recorded before any row is deleted" a database-enforced
-- rule rather than a convention of the job.
-- Depends on: 000004, 000086

CREATE OR REPLACE FUNCTION prevent_audit_log_mutation()
RETURNS trigger AS $f$
BEGIN
    IF TG_OP = 'DELETE' AND current_setting('kryptkeeper.audit_archive', true) = 'on' THEN
        -- Nested so audit_archives is only resolved when the archive job has
        -- opted in: a plain UPDATE/DELETE must raise "append-only" even on
        -- a database where that table does not exist yet.
        IF EXISTS (
            SELECT 1 FROM audit_archives a
             WHERE OLD.id BETWEEN a.first_id AND a.last_id
               AND OLD.timestamp < a.before_ts::timestamptz
        ) THEN
            RETURN OLD;
        END IF;
    END IF;
    RAISE EXCEPTION 'audit_log is append-only';
END;
$f$ LANGUAGE plpgsql;
