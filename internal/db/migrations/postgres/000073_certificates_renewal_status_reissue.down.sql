-- (Postgres)
-- Rollback for 000073: restore the four-value vocabulary. Flagged rows are
-- reset to 'active' first so the narrower constraint accepts them.
UPDATE certificates SET renewal_status = 'active' WHERE renewal_status = 'reissue_required';
ALTER TABLE certificates DROP CONSTRAINT IF EXISTS certificates_renewal_status_check;
ALTER TABLE certificates ADD CONSTRAINT certificates_renewal_status_check
    CHECK (renewal_status IN ('active', 'renewed', 'expired', 'revoked'));
