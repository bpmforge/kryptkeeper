-- Rollback W9 (SQLite): SQLite does not support DROP COLUMN in older versions;
-- recreate the table without the added columns.

BEGIN;

CREATE TABLE certificate_authorities_backup AS SELECT
    id, name, display_name, type, certificate_fingerprint_sha256,
    parent_ca_id, key_storage_type, pkcs11_library_path, pkcs11_token_label,
    pkcs11_key_label, key_file_path, cloud_kms_key_id, status,
    crl_distribution_points, ocsp_service_url, created_at, updated_at
FROM certificate_authorities;

DROP TABLE certificate_authorities;

ALTER TABLE certificate_authorities_backup RENAME TO certificate_authorities;

COMMIT;
