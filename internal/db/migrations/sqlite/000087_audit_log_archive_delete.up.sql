-- (SQLite)
-- Purpose: W22-07. Nothing to change in the schema. SQLite cannot condition a
-- trigger on a session setting, so the archive job instead drops
-- trg_audit_log_no_delete and re-creates it inside the single transaction
-- that deletes the archived rows (DDL is transactional in SQLite), which
-- leaves the trigger in place for every other connection at all times.
-- The Postgres counterpart replaces prevent_audit_log_mutation().
-- Depends on: 000004, 000086
SELECT 1;
