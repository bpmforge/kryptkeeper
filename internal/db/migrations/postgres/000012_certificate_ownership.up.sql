-- Wave W12 (PostgreSQL)
-- Purpose: Add ownership metadata to certificates for Venafi-parity cert lifecycle management
-- Depends on: W2
-- Rollback pair: 000012_certificate_ownership.down.sql

BEGIN;

ALTER TABLE certificates ADD COLUMN IF NOT EXISTS owner_email  TEXT;
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS owner_team   TEXT;
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS service_name TEXT;
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS labels       JSONB NOT NULL DEFAULT '[]';

CREATE INDEX IF NOT EXISTS idx_certs_owner_email ON certificates(owner_email) WHERE owner_email IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_certs_owner_team  ON certificates(owner_team)  WHERE owner_team  IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_certs_service     ON certificates(service_name) WHERE service_name IS NOT NULL;

COMMENT ON COLUMN certificates.owner_email  IS 'Primary owner email — used for renewal notifications';
COMMENT ON COLUMN certificates.owner_team   IS 'Owning team identifier for RBAC and reporting';
COMMENT ON COLUMN certificates.service_name IS 'Workload or service that uses this certificate';
COMMENT ON COLUMN certificates.labels       IS 'Arbitrary key=value tags for filtering';

COMMIT;
