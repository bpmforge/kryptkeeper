-- Wave W12 (SQLite)
-- Purpose: Add ownership metadata to certificates for Venafi-parity cert lifecycle management
-- Depends on: W2
-- Rollback pair: 000012_certificate_ownership.down.sql

BEGIN;

ALTER TABLE certificates ADD COLUMN owner_email  TEXT;
ALTER TABLE certificates ADD COLUMN owner_team   TEXT;
ALTER TABLE certificates ADD COLUMN service_name TEXT;
ALTER TABLE certificates ADD COLUMN labels       TEXT DEFAULT '[]';

CREATE INDEX IF NOT EXISTS idx_certs_owner_email ON certificates(owner_email) WHERE owner_email IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_certs_owner_team  ON certificates(owner_team)  WHERE owner_team  IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_certs_service     ON certificates(service_name) WHERE service_name IS NOT NULL;

COMMIT;
