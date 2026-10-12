-- Wave W2 (PostgreSQL)
-- Purpose: templates + CA + certificates core
-- Depends on: W1
-- Rollback pair: 000002_templates_ca_certs_core.down.sql

BEGIN;

CREATE TABLE IF NOT EXISTS certificate_templates (
    id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                      VARCHAR(255) NOT NULL UNIQUE,
    display_name              VARCHAR(255) NOT NULL,
    oid                       VARCHAR(128),
    allowed_algorithms        TEXT[] NOT NULL DEFAULT '{RSA,ECDSA,Ed25519}',
    min_key_size              INTEGER NOT NULL DEFAULT 2048,
    key_usage                 TEXT[] NOT NULL DEFAULT '{}',
    extended_key_usage        TEXT[] NOT NULL DEFAULT '{}',
    validity_period           INTERVAL NOT NULL DEFAULT '365 days',
    renewal_overlap           INTERVAL NOT NULL DEFAULT '30 days',
    max_validity_period       INTERVAL,
    subject_requirements      JSONB NOT NULL DEFAULT '{}',
    enrollment_permissions    JSONB NOT NULL DEFAULT '{"allow_all": true}',
    issuance_requirements     JSONB NOT NULL DEFAULT '{}',
    auto_enroll               BOOLEAN NOT NULL DEFAULT FALSE,
    active                    BOOLEAN NOT NULL DEFAULT TRUE,
    schema_version            SMALLINT NOT NULL DEFAULT 2,
    revision                  INTEGER NOT NULL DEFAULT 1,
    ad_sync_status            VARCHAR(20) DEFAULT 'not_synced'
                              CHECK (ad_sync_status IN ('not_synced', 'synced', 'sync_error', 'pending')),
    ad_last_synced_at         TIMESTAMPTZ,
    description               TEXT,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS certificate_authorities (
    id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                      VARCHAR(255) NOT NULL,
    display_name              VARCHAR(255) NOT NULL,
    type                      VARCHAR(20) NOT NULL
                              CHECK (type IN ('root', 'issuing', 'external')),
    certificate_fingerprint_sha256 VARCHAR(64),
    parent_ca_id              UUID REFERENCES certificate_authorities(id),
    key_storage_type          VARCHAR(20) NOT NULL
                              CHECK (key_storage_type IN ('software', 'pkcs11', 'cloud_kms', 'external')),
    pkcs11_library_path       VARCHAR(512),
    pkcs11_token_label        VARCHAR(255),
    pkcs11_key_label          VARCHAR(255),
    key_file_path             VARCHAR(512),
    cloud_kms_key_id          VARCHAR(512),
    status                    VARCHAR(20) NOT NULL DEFAULT 'active'
                              CHECK (status IN ('active', 'suspended', 'revoked', 'expired')),
    crl_distribution_points   TEXT[],
    ocsp_service_url          TEXT,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ca_root_has_no_parent CHECK (
        type != 'root' OR parent_ca_id IS NULL
    ),
    CONSTRAINT ca_issuing_has_parent CHECK (
        type NOT IN ('issuing') OR parent_ca_id IS NOT NULL
    )
);

CREATE TABLE IF NOT EXISTS certificates (
    fingerprint_sha256        VARCHAR(64) PRIMARY KEY,
    serial_number             VARCHAR(128) NOT NULL,
    subject_dn                TEXT NOT NULL,
    common_name               VARCHAR(255),
    subject_alt_names         TEXT[],
    issuer_dn                 TEXT NOT NULL,
    issuer_cn                 VARCHAR(255),
    ca_id                     UUID REFERENCES certificate_authorities(id),
    template_id               UUID REFERENCES certificate_templates(id),
    team_id                   UUID REFERENCES teams(id),
    valid_from                TIMESTAMPTZ NOT NULL,
    valid_until               TIMESTAMPTZ NOT NULL,
    public_key_algorithm      VARCHAR(20) NOT NULL
                              CHECK (public_key_algorithm IN ('RSA', 'ECDSA', 'Ed25519', 'ML-DSA')),
    key_size_bits             INTEGER,
    signature_algorithm       VARCHAR(50) NOT NULL,
    extended_key_usage        TEXT[],
    key_usage                 TEXT[],
    chain_complete            BOOLEAN NOT NULL DEFAULT FALSE,
    chain_trusted             BOOLEAN NOT NULL DEFAULT FALSE,
    pqc_vulnerable            BOOLEAN NOT NULL DEFAULT FALSE,
    risk_score                SMALLINT NOT NULL DEFAULT 0
                              CHECK (risk_score >= 0 AND risk_score <= 100),
    risk_flags                TEXT[] NOT NULL DEFAULT '{}',
    grade                     CHAR(1) NOT NULL DEFAULT 'A'
                              CHECK (grade IN ('A', 'B', 'C', 'D', 'F')),
    renewal_method            VARCHAR(20)
                              CHECK (renewal_method IN ('acme', 'est', 'scep', 'api', 'manual', NULL)),
    renewal_status            VARCHAR(20) DEFAULT 'active'
                              CHECK (renewal_status IN ('active', 'renewed', 'expired', 'revoked')),
    predecessor_fingerprint   VARCHAR(64) REFERENCES certificates(fingerprint_sha256),
    successor_fingerprint     VARCHAR(64) REFERENCES certificates(fingerprint_sha256),
    revoked_at                TIMESTAMPTZ,
    revocation_reason         SMALLINT,
    source                    VARCHAR(20) NOT NULL DEFAULT 'api'
                              CHECK (source IN ('api', 'acme', 'est', 'scep', 'discovery_network',
                                               'discovery_ssh', 'discovery_winrm', 'discovery_agent',
                                               'discovery_cloud', 'discovery_k8s', 'ct_log', 'import')),
    raw_cert_b64              TEXT,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE certificate_authorities
    ADD CONSTRAINT ca_certificate_fingerprint_fk
    FOREIGN KEY (certificate_fingerprint_sha256)
    REFERENCES certificates(fingerprint_sha256);

CREATE UNIQUE INDEX IF NOT EXISTS idx_cert_serial_ca ON certificates(serial_number, ca_id);
CREATE INDEX IF NOT EXISTS idx_cert_valid_until ON certificates(valid_until);
CREATE INDEX IF NOT EXISTS idx_cert_risk_score ON certificates(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_cert_grade ON certificates(grade);
CREATE INDEX IF NOT EXISTS idx_cert_renewal_status ON certificates(renewal_status);
CREATE INDEX IF NOT EXISTS idx_cert_team ON certificates(team_id);
CREATE INDEX IF NOT EXISTS idx_cert_ca ON certificates(ca_id);
CREATE INDEX IF NOT EXISTS idx_cert_common_name ON certificates(common_name);
CREATE INDEX IF NOT EXISTS idx_cert_sans ON certificates USING GIN (subject_alt_names);
CREATE INDEX IF NOT EXISTS idx_cert_risk_flags ON certificates USING GIN (risk_flags);

CREATE INDEX IF NOT EXISTS idx_ca_parent ON certificate_authorities(parent_ca_id);
CREATE INDEX IF NOT EXISTS idx_ca_status ON certificate_authorities(status);

CREATE INDEX IF NOT EXISTS idx_template_active ON certificate_templates(active);
CREATE INDEX IF NOT EXISTS idx_template_oid ON certificate_templates(oid);

DROP TRIGGER IF EXISTS trg_certificate_templates_set_updated_at ON certificate_templates;
CREATE TRIGGER trg_certificate_templates_set_updated_at
BEFORE UPDATE ON certificate_templates
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS trg_certificate_authorities_set_updated_at ON certificate_authorities;
CREATE TRIGGER trg_certificate_authorities_set_updated_at
BEFORE UPDATE ON certificate_authorities
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS trg_certificates_set_updated_at ON certificates;
CREATE TRIGGER trg_certificates_set_updated_at
BEFORE UPDATE ON certificates
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

COMMIT;
