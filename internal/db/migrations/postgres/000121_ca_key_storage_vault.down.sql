-- Rollback pair of 000121. A vault-backed CA has no valid representation under
-- the original CHECK; it is relabelled `external` first (the closest old value:
-- key custody outside the hub's own keystore).

BEGIN;

UPDATE certificate_authorities SET key_storage_type = 'external' WHERE key_storage_type = 'vault';
ALTER TABLE certificate_authorities DROP CONSTRAINT IF EXISTS certificate_authorities_key_storage_type_check;
ALTER TABLE certificate_authorities ADD CONSTRAINT certificate_authorities_key_storage_type_check
    CHECK (key_storage_type IN ('software', 'pkcs11', 'cloud_kms', 'external'));

COMMIT;
