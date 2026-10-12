-- Wave W8 (PostgreSQL)
-- Purpose: in-app runtime configuration store, env -> DB overrides (W8-03, D-068, FR-P30)
-- Depends on: none
-- Rollback pair: 000030_runtime_config.down.sql

BEGIN;

CREATE TABLE IF NOT EXISTS runtime_config (
    key         TEXT PRIMARY KEY,
    value       TEXT,
    envelope    TEXT,
    updated_at  TEXT NOT NULL,
    updated_by  TEXT
);

COMMIT;
