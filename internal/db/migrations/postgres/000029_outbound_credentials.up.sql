-- Wave W5 (PostgreSQL)
-- Purpose: outbound credential store, encrypted at rest (W5-10, D-063, FR-P25)
-- Depends on: none
-- Rollback pair: 000029_outbound_credentials.down.sql

BEGIN;

CREATE TABLE IF NOT EXISTS outbound_credentials (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    credential_type TEXT NOT NULL
                    CHECK (credential_type IN ('ssh_key', 'api_token', 'cloud_iam')),
    tenant          TEXT NOT NULL DEFAULT 'default',
    envelope        TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_outbound_credentials_tenant ON outbound_credentials(tenant);

COMMIT;
