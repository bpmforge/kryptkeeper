-- W35-01: per-connector upstream Retry-After hold, shared by restarts and replicas.
-- Rollback pair: 000360_connector_retry_gate.down.sql
BEGIN;

CREATE TABLE IF NOT EXISTS connector_retry_gate (
    connector_id TEXT PRIMARY KEY,
    retry_at     TIMESTAMPTZ NOT NULL,
    reason       TEXT NOT NULL,
    updated_at   TIMESTAMPTZ NOT NULL
);

COMMIT;
