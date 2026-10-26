-- W27-39: append-only log of admitted CA orders behind the rolling-window budget.
-- Rollback pair: 000361_connector_issue_log.down.sql
BEGIN;

CREATE TABLE IF NOT EXISTS connector_issue_log (
    connector_id TEXT NOT NULL,
    issued_at    TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_connector_issue_log ON connector_issue_log (connector_id, issued_at);

COMMIT;
