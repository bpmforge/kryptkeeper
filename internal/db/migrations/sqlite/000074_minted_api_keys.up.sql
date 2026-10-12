-- (SQLite)
-- Purpose: persist API keys minted via POST /api/v1/api-keys. They were held
-- in process memory only, so every restart turned a working key into a 401.
-- The legacy api_keys table (000001) cannot hold them: it requires a users FK
-- and a key_hash, and has no principal_id / role / created_by / tenant.
-- Only the HMAC verifier is stored, never the secret.
-- Depends on: none
-- Rollback pair: 000074_minted_api_keys.down.sql
CREATE TABLE IF NOT EXISTS minted_api_keys (
    kid             TEXT PRIMARY KEY,
    name            TEXT NOT NULL DEFAULT '',
    secret_verifier TEXT NOT NULL,
    principal_id    TEXT NOT NULL,
    role            TEXT NOT NULL DEFAULT 'service-account',
    scopes          TEXT NOT NULL DEFAULT '[]',
    active          INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL,
    created_by      TEXT NOT NULL DEFAULT '',
    expires_at      TEXT NOT NULL DEFAULT '',
    last_used_at    TEXT NOT NULL DEFAULT '',
    revoked_at      TEXT NOT NULL DEFAULT '',
    tenant          TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_minted_api_keys_active ON minted_api_keys(active);
