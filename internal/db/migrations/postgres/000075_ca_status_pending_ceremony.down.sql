-- Rollback pair of 000075. A CA parked pending_ceremony has no valid
-- representation under the original CHECK, so it is suspended first.

BEGIN;

UPDATE certificate_authorities SET status = 'suspended' WHERE status = 'pending_ceremony';
ALTER TABLE certificate_authorities DROP CONSTRAINT IF EXISTS certificate_authorities_status_check;
ALTER TABLE certificate_authorities ADD CONSTRAINT certificate_authorities_status_check
    CHECK (status IN ('active', 'suspended', 'revoked', 'expired'));

COMMIT;
