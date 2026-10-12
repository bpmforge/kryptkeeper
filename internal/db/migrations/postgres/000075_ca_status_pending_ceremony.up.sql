-- rc.5: root-CA key ceremonies (W9-06) park the new CA as `pending_ceremony`,
-- but certificate_authorities.status CHECK never allowed that value, so
-- StartRootCACeremony failed against a real database on both engines after
-- the root CA had already been created active. Widens the CHECK.
-- Depends on: 000002
-- Rollback pair: 000075_ca_status_pending_ceremony.down.sql

BEGIN;

ALTER TABLE certificate_authorities DROP CONSTRAINT IF EXISTS certificate_authorities_status_check;
ALTER TABLE certificate_authorities ADD CONSTRAINT certificate_authorities_status_check
    CHECK (status IN ('active', 'suspended', 'revoked', 'expired', 'pending_ceremony'));

COMMIT;
