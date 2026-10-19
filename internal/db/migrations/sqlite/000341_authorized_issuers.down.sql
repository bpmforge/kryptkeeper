-- Rollback pair of 000341. The column drop needs SQLite 3.35+ (the bundled
-- modernc driver is newer); the CHECK on issuer_class is column-level, so it
-- goes with the column.
ALTER TABLE certificates DROP COLUMN issuer_class;
DROP INDEX IF EXISTS idx_authorized_issuers_identity;
DROP TABLE IF EXISTS authorized_issuers;
