-- W11-03 (V5/D-106): issuer connectors — persisted config for the issuer
-- abstraction. Credentials live in outbound_credentials (W5-10), referenced
-- by credential_ref; config_json holds no secrets.
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
-- The renewal path a takeover chose (W11-03): nullable, no CHECK — connector
-- ids are rows, not enums.
ALTER TABLE certificates ADD COLUMN renewal_connector_id TEXT;
