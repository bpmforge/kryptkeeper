-- W23-10: record the key backend on every CA row. The engine labels a
-- Vault-held key "vault", which the key_storage_type CHECK never allowed, so CA
-- creation failed against a real database on KRYPTKEEPER_KEY_BACKEND=vault.
-- Widens the CHECK to the canonical vocabulary.
-- Rollback pair: 000121_ca_key_storage_vault.down.sql

BEGIN;

ALTER TABLE certificate_authorities DROP CONSTRAINT IF EXISTS certificate_authorities_key_storage_type_check;
ALTER TABLE certificate_authorities ADD CONSTRAINT certificate_authorities_key_storage_type_check
    CHECK (key_storage_type IN ('software', 'pkcs11', 'vault', 'cloud_kms', 'external'));

COMMIT;
