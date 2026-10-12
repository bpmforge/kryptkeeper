-- (Postgres)
-- Rollback for 000074: drops every persisted minted API key.
DROP INDEX IF EXISTS idx_minted_api_keys_active;
DROP TABLE IF EXISTS minted_api_keys;
