-- Wave W4 (SQLite)
-- Purpose: audit_log with append-only controls
-- Depends on: W1
-- Rollback pair: 000004_audit_log_append_only.down.sql

BEGIN;

CREATE TABLE IF NOT EXISTS audit_log (
    id                        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp                 TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    action                    TEXT NOT NULL,
    actor_type                TEXT NOT NULL CHECK (actor_type IN ('user', 'api_key', 'system', 'agent')),
    actor_id                  TEXT NOT NULL,
    actor_email               TEXT,
    resource_type             TEXT NOT NULL,
    resource_id               TEXT NOT NULL,
    client_ip                 TEXT,
    trace_id                  TEXT,
    details                   TEXT NOT NULL DEFAULT '{}',
    diff                      TEXT,
    outcome                   TEXT NOT NULL DEFAULT 'success' CHECK (outcome IN ('success', 'failure', 'denied'))
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_log(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor_id);

CREATE TRIGGER IF NOT EXISTS trg_audit_log_no_update
BEFORE UPDATE ON audit_log
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;

CREATE TRIGGER IF NOT EXISTS trg_audit_log_no_delete
BEFORE DELETE ON audit_log
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;

COMMIT;
