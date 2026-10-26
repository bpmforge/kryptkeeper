-- Purpose: W38-07 (D-324). Target credentials can come from an external secret
-- manager at use time. credential_sources holds where to fetch from (HashiCorp
-- Vault or OpenBao KV v2, or a `credentials` plugin) and a credential_ref to a
-- LOCAL api_token credential that authenticates to it; outbound_credentials
-- gains source / source_id / source_ref, where an external row stores only a
-- reference (path, version), never a secret.
-- ADD COLUMN IF NOT EXISTS: the credential stores self-heal the same columns and table.
-- Depends on: 000029
-- Rollback pair: 000386_credential_sources.down.sql

CREATE TABLE IF NOT EXISTS credential_sources (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    kind           TEXT NOT NULL CHECK (kind IN ('vault_kv2', 'plugin')),
    tenant         TEXT NOT NULL DEFAULT 'default',
    config         TEXT NOT NULL,
    credential_ref TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_credential_sources_tenant ON credential_sources(tenant);

ALTER TABLE outbound_credentials ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'local';
ALTER TABLE outbound_credentials ADD COLUMN IF NOT EXISTS source_id TEXT;
ALTER TABLE outbound_credentials ADD COLUMN IF NOT EXISTS source_ref TEXT;
