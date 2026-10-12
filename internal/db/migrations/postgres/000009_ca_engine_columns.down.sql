-- Rollback W9 (Postgres)

BEGIN;

ALTER TABLE certificate_authorities DROP COLUMN IF EXISTS cert_pem;
ALTER TABLE certificate_authorities DROP COLUMN IF EXISTS key_id;

COMMIT;
