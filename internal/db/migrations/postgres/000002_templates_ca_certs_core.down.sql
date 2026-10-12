-- Wave W2 rollback (PostgreSQL)
-- Paired with: 000002_templates_ca_certs_core.up.sql

BEGIN;

DROP TRIGGER IF EXISTS trg_certificates_set_updated_at ON certificates;
DROP TRIGGER IF EXISTS trg_certificate_authorities_set_updated_at ON certificate_authorities;
DROP TRIGGER IF EXISTS trg_certificate_templates_set_updated_at ON certificate_templates;

ALTER TABLE certificate_authorities
    DROP CONSTRAINT IF EXISTS ca_certificate_fingerprint_fk;

DROP INDEX IF EXISTS idx_template_oid;
DROP INDEX IF EXISTS idx_template_active;
DROP INDEX IF EXISTS idx_ca_status;
DROP INDEX IF EXISTS idx_ca_parent;
DROP INDEX IF EXISTS idx_cert_risk_flags;
DROP INDEX IF EXISTS idx_cert_sans;
DROP INDEX IF EXISTS idx_cert_common_name;
DROP INDEX IF EXISTS idx_cert_ca;
DROP INDEX IF EXISTS idx_cert_team;
DROP INDEX IF EXISTS idx_cert_renewal_status;
DROP INDEX IF EXISTS idx_cert_grade;
DROP INDEX IF EXISTS idx_cert_risk_score;
DROP INDEX IF EXISTS idx_cert_valid_until;
DROP INDEX IF EXISTS idx_cert_serial_ca;

DROP TABLE IF EXISTS certificates;
DROP TABLE IF EXISTS certificate_authorities;
DROP TABLE IF EXISTS certificate_templates;

COMMIT;
