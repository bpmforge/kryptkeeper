-- Rollback pair of 000341.
ALTER TABLE certificates DROP COLUMN IF EXISTS issuer_class;
DROP INDEX IF EXISTS idx_authorized_issuers_identity;
DROP TABLE IF EXISTS authorized_issuers;
