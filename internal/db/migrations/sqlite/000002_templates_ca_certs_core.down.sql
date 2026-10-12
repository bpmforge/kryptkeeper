-- Wave W2 rollback (SQLite)
-- Paired with: 000002_templates_ca_certs_core.up.sql

BEGIN;

DROP TRIGGER IF EXISTS trg_ca_certificate_fingerprint_fk_upd;
DROP TRIGGER IF EXISTS trg_ca_certificate_fingerprint_fk_ins;
DROP TRIGGER IF EXISTS trg_certificates_set_updated_at;
DROP TRIGGER IF EXISTS trg_certificate_authorities_set_updated_at;
DROP TRIGGER IF EXISTS trg_certificate_templates_set_updated_at;

DROP INDEX IF EXISTS idx_template_oid;
DROP INDEX IF EXISTS idx_template_active;
DROP INDEX IF EXISTS idx_ca_status;
DROP INDEX IF EXISTS idx_ca_parent;
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
