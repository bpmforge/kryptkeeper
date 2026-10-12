-- (Postgres)
-- Purpose: add 'reissue_required' to certificates.renewal_status's CHECK
-- constraint (see the SQLite twin). The inline column CHECK from 000002 was
-- auto-named certificates_renewal_status_check.
-- Depends on: 000002
-- Rollback pair: 000073_certificates_renewal_status_reissue.down.sql
ALTER TABLE certificates DROP CONSTRAINT IF EXISTS certificates_renewal_status_check;
ALTER TABLE certificates ADD CONSTRAINT certificates_renewal_status_check
    CHECK (renewal_status IN ('active', 'renewed', 'expired', 'revoked', 'reissue_required'));
