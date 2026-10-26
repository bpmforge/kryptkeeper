-- W27-39: append-only log of admitted CA orders behind the rolling-window budget.
-- issued_at is fixed-width UTC text (2006-01-02T15:04:05.000000000Z) so SQL string comparison orders it.
CREATE TABLE IF NOT EXISTS connector_issue_log (
    connector_id TEXT NOT NULL,
    issued_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_connector_issue_log ON connector_issue_log (connector_id, issued_at);
