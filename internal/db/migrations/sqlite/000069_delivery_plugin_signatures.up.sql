-- Wave W20 (SQLite) (W20-24, D-117): keep each plugin version's signature
-- and the id (sha256 of the PKIX public key) of the key that verified it, so
-- the trust tier shown can be re-checked from what is stored.
-- Depends on: 000067
-- Rollback pair: 000069_delivery_plugin_signatures.down.sql

ALTER TABLE delivery_plugin_versions ADD COLUMN signature TEXT NOT NULL DEFAULT '';
ALTER TABLE delivery_plugin_versions ADD COLUMN signer_key_id TEXT NOT NULL DEFAULT '';
