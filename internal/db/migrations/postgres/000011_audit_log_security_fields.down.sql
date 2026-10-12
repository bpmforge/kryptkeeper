-- Wave W11 (PostgreSQL) - rollback

BEGIN;

ALTER TABLE audit_log DROP COLUMN IF EXISTS source_ip;
ALTER TABLE audit_log DROP COLUMN IF EXISTS user_agent;
ALTER TABLE audit_log DROP COLUMN IF EXISTS session_id;
ALTER TABLE audit_log DROP COLUMN IF EXISTS change_summary;

COMMIT;
