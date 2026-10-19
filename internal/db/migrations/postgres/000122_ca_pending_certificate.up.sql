-- W23-04: issuing-CA CSR flow. Adds certificate_authorities.csr_pem and the
-- `pending_certificate` status: a CA whose key and CSR exist but whose
-- offline-signed certificate has not been uploaded yet.
-- Rollback pair: 000122_ca_pending_certificate.down.sql

BEGIN;

ALTER TABLE certificate_authorities ADD COLUMN IF NOT EXISTS csr_pem TEXT;
ALTER TABLE certificate_authorities DROP CONSTRAINT IF EXISTS certificate_authorities_status_check;
ALTER TABLE certificate_authorities ADD CONSTRAINT certificate_authorities_status_check
    CHECK (status IN ('active', 'suspended', 'revoked', 'expired', 'pending_ceremony', 'pending_certificate'));

COMMIT;
