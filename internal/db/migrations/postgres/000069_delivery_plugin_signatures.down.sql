BEGIN;

ALTER TABLE delivery_plugin_versions DROP COLUMN IF EXISTS signer_key_id;
ALTER TABLE delivery_plugin_versions DROP COLUMN IF EXISTS signature;

COMMIT;
