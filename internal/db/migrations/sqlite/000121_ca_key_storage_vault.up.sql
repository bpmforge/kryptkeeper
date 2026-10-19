-- W23-10: record the key backend on every CA row. The engine labels a
-- Vault-held key "vault", which the key_storage_type CHECK never allowed, so CA
-- creation failed against a real database on KRYPTKEEPER_KEY_BACKEND=vault.
-- Widens the CHECK to the canonical vocabulary. SQLite cannot alter a CHECK,
-- so this is the 000075 rebuild with the new value (all columns, indexes and
-- triggers preserved).

PRAGMA foreign_keys=OFF;

BEGIN;

CREATE TABLE certificate_authorities_new (
    id                        TEXT PRIMARY KEY,
    name                      TEXT NOT NULL,
    display_name              TEXT NOT NULL,
    type                      TEXT NOT NULL CHECK (type IN ('root', 'issuing', 'external')),
    certificate_fingerprint_sha256 TEXT,
    parent_ca_id              TEXT REFERENCES certificate_authorities(id),
    key_storage_type          TEXT NOT NULL CHECK (key_storage_type IN ('software', 'pkcs11', 'vault', 'cloud_kms', 'external')),
    pkcs11_library_path       TEXT,
    pkcs11_token_label        TEXT,
    pkcs11_key_label          TEXT,
    key_file_path             TEXT,
    cloud_kms_key_id          TEXT,
    status                    TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'revoked', 'expired', 'pending_ceremony')),
    crl_distribution_points   TEXT,
    ocsp_service_url          TEXT,
    created_at                TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at                TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    cert_pem                  TEXT,
    key_id                    TEXT,
    CONSTRAINT ca_root_has_no_parent CHECK (type != 'root' OR parent_ca_id IS NULL),
    CONSTRAINT ca_issuing_has_parent CHECK (type NOT IN ('issuing') OR parent_ca_id IS NOT NULL)
);

INSERT INTO certificate_authorities_new (id, name, display_name, type, certificate_fingerprint_sha256,
    parent_ca_id, key_storage_type, pkcs11_library_path, pkcs11_token_label, pkcs11_key_label,
    key_file_path, cloud_kms_key_id, status, crl_distribution_points, ocsp_service_url,
    created_at, updated_at, cert_pem, key_id)
SELECT id, name, display_name, type, certificate_fingerprint_sha256,
    parent_ca_id, key_storage_type, pkcs11_library_path, pkcs11_token_label, pkcs11_key_label,
    key_file_path, cloud_kms_key_id, status, crl_distribution_points, ocsp_service_url,
    created_at, updated_at, cert_pem, key_id
FROM certificate_authorities;

DROP TABLE certificate_authorities;
ALTER TABLE certificate_authorities_new RENAME TO certificate_authorities;

CREATE INDEX IF NOT EXISTS idx_ca_parent ON certificate_authorities(parent_ca_id);
CREATE INDEX IF NOT EXISTS idx_ca_status ON certificate_authorities(status);

CREATE TRIGGER IF NOT EXISTS trg_certificate_authorities_set_updated_at
AFTER UPDATE ON certificate_authorities
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE certificate_authorities
       SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
     WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS trg_ca_certificate_fingerprint_fk_ins
BEFORE INSERT ON certificate_authorities
FOR EACH ROW
WHEN NEW.certificate_fingerprint_sha256 IS NOT NULL
     AND NOT EXISTS (
         SELECT 1 FROM certificates
          WHERE fingerprint_sha256 = NEW.certificate_fingerprint_sha256
     )
BEGIN
    SELECT RAISE(ABORT, 'ca_certificate_fingerprint_fk violation');
END;

CREATE TRIGGER IF NOT EXISTS trg_ca_certificate_fingerprint_fk_upd
BEFORE UPDATE OF certificate_fingerprint_sha256 ON certificate_authorities
FOR EACH ROW
WHEN NEW.certificate_fingerprint_sha256 IS NOT NULL
     AND NOT EXISTS (
         SELECT 1 FROM certificates
          WHERE fingerprint_sha256 = NEW.certificate_fingerprint_sha256
     )
BEGIN
    SELECT RAISE(ABORT, 'ca_certificate_fingerprint_fk violation');
END;

COMMIT;

PRAGMA foreign_keys=ON;
