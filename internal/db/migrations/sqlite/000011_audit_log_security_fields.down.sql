-- Wave W11 (SQLite) - rollback
-- SQLite does not support DROP COLUMN in older versions; recreate without the new columns.

BEGIN;

CREATE TABLE audit_log_rollback AS SELECT
    id, timestamp, action, actor_type, actor_id, resource_type, resource_id, trace_id, outcome
FROM audit_log;

DROP TABLE audit_log;

ALTER TABLE audit_log_rollback RENAME TO audit_log;

COMMIT;
