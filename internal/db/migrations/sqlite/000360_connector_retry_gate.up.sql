-- W35-01: per-connector upstream Retry-After hold, shared by restarts and replicas.
-- Timestamps are fixed-width UTC text (2006-01-02T15:04:05.000000000Z) so SQL string comparison orders them.
CREATE TABLE IF NOT EXISTS connector_retry_gate (
    connector_id TEXT PRIMARY KEY,
    retry_at     TEXT NOT NULL,
    reason       TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);
