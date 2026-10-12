-- W11-05 (PostgreSQL) — direct-CA inventory sources.
-- Depends on: 000002
-- Rollback pair: 000045_inventory_sources.down.sql

BEGIN;

CREATE TABLE IF NOT EXISTS inventory_sources (
    id               TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    type             TEXT NOT NULL CHECK (type IN ('adcs_export', 'digicert')),
    config_json      TEXT NOT NULL DEFAULT '{}',
    credential_ref   TEXT,
    schedule_minutes INTEGER NOT NULL DEFAULT 0
                     CHECK (schedule_minutes >= 0),
    tenant           TEXT NOT NULL DEFAULT 'default',
    last_sync_at     TEXT,
    last_sync_result TEXT,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_inventory_sources_tenant ON inventory_sources(tenant);

COMMIT;
