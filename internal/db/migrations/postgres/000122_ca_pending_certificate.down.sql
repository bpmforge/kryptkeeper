-- Rollback pair of 000122. A CA parked pending_certificate has no valid
-- representation under the previous CHECK, so it is suspended first (it was not
-- usable for issuance either way); csr_pem is dropped.

BEGIN;

UPDATE certificate_authorities SET status = 'suspended' WHERE status = 'pending_certificate';
ALTER TABLE certificate_authorities DROP CONSTRAINT IF EXISTS certificate_authorities_status_check;
ALTER TABLE certificate_authorities ADD CONSTRAINT certificate_authorities_status_check
    CHECK (status IN ('active', 'suspended', 'revoked', 'expired', 'pending_ceremony'));
ALTER TABLE certificate_authorities DROP COLUMN IF EXISTS csr_pem;

COMMIT;
