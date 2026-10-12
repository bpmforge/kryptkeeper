-- W11-03 (PostgreSQL) — issuer connectors + chosen renewal path.
-- Depends on: 000002 (certificates)
-- Rollback pair: 000044_issuer_connectors.down.sql

BEGIN;

CREATE TABLE IF NOT EXISTS connectors (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    type           TEXT NOT NULL CHECK (type IN ('internal', 'acme')),
    config_json    TEXT NOT NULL DEFAULT '{}',
    credential_ref TEXT,
    tenant         TEXT NOT NULL DEFAULT 'default',
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_connectors_tenant ON connectors(tenant);
ALTER TABLE certificates ADD COLUMN renewal_connector_id TEXT;

COMMIT;
