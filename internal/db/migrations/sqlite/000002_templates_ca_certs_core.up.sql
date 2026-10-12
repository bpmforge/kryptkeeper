-- Wave W2 (SQLite)
-- Purpose: templates + CA + certificates core
-- Depends on: W1
-- Rollback pair: 000002_templates_ca_certs_core.down.sql

BEGIN;

CREATE TABLE IF NOT EXISTS certificate_templates (
    id                        TEXT PRIMARY KEY,
    name                      TEXT NOT NULL UNIQUE,
    display_name              TEXT NOT NULL,
    oid                       TEXT,
    allowed_algorithms        TEXT NOT NULL DEFAULT '["RSA","ECDSA","Ed25519"]',
    min_key_size              INTEGER NOT NULL DEFAULT 2048,
    key_usage                 TEXT NOT NULL DEFAULT '[]',
    extended_key_usage        TEXT NOT NULL DEFAULT '[]',
    validity_period           TEXT NOT NULL DEFAULT '365 days',
    renewal_overlap           TEXT NOT NULL DEFAULT '30 days',
    max_validity_period       TEXT,
    subject_requirements      TEXT NOT NULL DEFAULT '{}',
    enrollment_permissions    TEXT NOT NULL DEFAULT '{"allow_all":true}',
    issuance_requirements     TEXT NOT NULL DEFAULT '{}',
    auto_enroll               INTEGER NOT NULL DEFAULT 0 CHECK (auto_enroll IN (0,1)),
    active                    INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
    schema_version            INTEGER NOT NULL DEFAULT 2,
    revision                  INTEGER NOT NULL DEFAULT 1,
    ad_sync_status            TEXT DEFAULT 'not_synced'
                              CHECK (ad_sync_status IN ('not_synced', 'synced', 'sync_error', 'pending')),
    ad_last_synced_at         TEXT,
    description               TEXT,
    created_at                TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at                TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS certificate_authorities (
    id                        TEXT PRIMARY KEY,
    name                      TEXT NOT NULL,
    display_name              TEXT NOT NULL,
    type                      TEXT NOT NULL CHECK (type IN ('root', 'issuing', 'external')),
    certificate_fingerprint_sha256 TEXT,
    parent_ca_id              TEXT REFERENCES certificate_authorities(id),
    key_storage_type          TEXT NOT NULL CHECK (key_storage_type IN ('software', 'pkcs11', 'cloud_kms', 'external')),
    pkcs11_library_path       TEXT,
    pkcs11_token_label        TEXT,
    pkcs11_key_label          TEXT,
    key_file_path             TEXT,
    cloud_kms_key_id          TEXT,
    status                    TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'revoked', 'expired')),
    crl_distribution_points   TEXT,
    ocsp_service_url          TEXT,
    created_at                TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at                TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    CONSTRAINT ca_root_has_no_parent CHECK (type != 'root' OR parent_ca_id IS NULL),
    CONSTRAINT ca_issuing_has_parent CHECK (type NOT IN ('issuing') OR parent_ca_id IS NOT NULL)
);

CREATE TABLE IF NOT EXISTS certificates (
    fingerprint_sha256        TEXT PRIMARY KEY,
    serial_number             TEXT NOT NULL,
    subject_dn                TEXT NOT NULL,
    common_name               TEXT,
    subject_alt_names         TEXT,
    issuer_dn                 TEXT NOT NULL,
    issuer_cn                 TEXT,
    ca_id                     TEXT REFERENCES certificate_authorities(id),
    template_id               TEXT REFERENCES certificate_templates(id),
    team_id                   TEXT REFERENCES teams(id),
    valid_from                TEXT NOT NULL,
    valid_until               TEXT NOT NULL,
    public_key_algorithm      TEXT NOT NULL CHECK (public_key_algorithm IN ('RSA', 'ECDSA', 'Ed25519', 'ML-DSA')),
    key_size_bits             INTEGER,
    signature_algorithm       TEXT NOT NULL,
    extended_key_usage        TEXT,
    key_usage                 TEXT,
    chain_complete            INTEGER NOT NULL DEFAULT 0 CHECK (chain_complete IN (0,1)),
    chain_trusted             INTEGER NOT NULL DEFAULT 0 CHECK (chain_trusted IN (0,1)),
    pqc_vulnerable            INTEGER NOT NULL DEFAULT 0 CHECK (pqc_vulnerable IN (0,1)),
    risk_score                INTEGER NOT NULL DEFAULT 0 CHECK (risk_score >= 0 AND risk_score <= 100),
    risk_flags                TEXT NOT NULL DEFAULT '[]',
    grade                     TEXT NOT NULL DEFAULT 'A' CHECK (grade IN ('A', 'B', 'C', 'D', 'F')),
    renewal_method            TEXT CHECK (renewal_method IN ('acme', 'est', 'scep', 'api', 'manual') OR renewal_method IS NULL),
    renewal_status            TEXT DEFAULT 'active' CHECK (renewal_status IN ('active', 'renewed', 'expired', 'revoked')),
    predecessor_fingerprint   TEXT REFERENCES certificates(fingerprint_sha256),
    successor_fingerprint     TEXT REFERENCES certificates(fingerprint_sha256),
    revoked_at                TEXT,
    revocation_reason         INTEGER,
    source                    TEXT NOT NULL DEFAULT 'api'
                              CHECK (source IN ('api', 'acme', 'est', 'scep', 'discovery_network',
                                               'discovery_ssh', 'discovery_winrm', 'discovery_agent',
                                               'discovery_cloud', 'discovery_k8s', 'ct_log', 'import')),
    raw_cert_b64              TEXT,
    created_at                TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at                TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_cert_serial_ca ON certificates(serial_number, ca_id);
CREATE INDEX IF NOT EXISTS idx_cert_valid_until ON certificates(valid_until);
CREATE INDEX IF NOT EXISTS idx_cert_risk_score ON certificates(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_cert_grade ON certificates(grade);
CREATE INDEX IF NOT EXISTS idx_cert_renewal_status ON certificates(renewal_status);
CREATE INDEX IF NOT EXISTS idx_cert_team ON certificates(team_id);
CREATE INDEX IF NOT EXISTS idx_cert_ca ON certificates(ca_id);
CREATE INDEX IF NOT EXISTS idx_cert_common_name ON certificates(common_name);

CREATE INDEX IF NOT EXISTS idx_ca_parent ON certificate_authorities(parent_ca_id);
CREATE INDEX IF NOT EXISTS idx_ca_status ON certificate_authorities(status);

CREATE INDEX IF NOT EXISTS idx_template_active ON certificate_templates(active);
CREATE INDEX IF NOT EXISTS idx_template_oid ON certificate_templates(oid);

CREATE TRIGGER IF NOT EXISTS trg_certificate_templates_set_updated_at
AFTER UPDATE ON certificate_templates
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE certificate_templates
       SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
     WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS trg_certificate_authorities_set_updated_at
AFTER UPDATE ON certificate_authorities
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE certificate_authorities
       SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
     WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS trg_certificates_set_updated_at
AFTER UPDATE ON certificates
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE certificates
       SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
     WHERE fingerprint_sha256 = NEW.fingerprint_sha256;
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
