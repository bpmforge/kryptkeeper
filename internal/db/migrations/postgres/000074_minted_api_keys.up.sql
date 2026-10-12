-- (Postgres)
-- Purpose: persist API keys minted via POST /api/v1/api-keys (see the SQLite
-- twin). Timestamps stay RFC3339 text to match the in-memory record; only the
-- HMAC verifier is stored, never the secret.
-- Depends on: none
-- Rollback pair: 000074_minted_api_keys.down.sql
CREATE TABLE IF NOT EXISTS minted_api_keys (
    kid             TEXT PRIMARY KEY,
    name            TEXT NOT NULL DEFAULT '',
    secret_verifier TEXT NOT NULL,
    principal_id    TEXT NOT NULL,
    role            TEXT NOT NULL DEFAULT 'service-account',
    scopes          TEXT NOT NULL DEFAULT '[]',
    active          BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TEXT NOT NULL,
    created_by      TEXT NOT NULL DEFAULT '',
    expires_at      TEXT NOT NULL DEFAULT '',
    last_used_at    TEXT NOT NULL DEFAULT '',
    revoked_at      TEXT NOT NULL DEFAULT '',
    tenant          TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_minted_api_keys_active ON minted_api_keys(active);
