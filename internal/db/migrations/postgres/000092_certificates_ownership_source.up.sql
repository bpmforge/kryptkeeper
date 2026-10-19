-- W22-24 (PostgreSQL): where a certificate's owner assignment came from
-- (manual|cmdb|import|agent). '' = unowned. Semantics identical to sqlite.
-- Rollback pair: 000092_certificates_ownership_source.down.sql

BEGIN;

ALTER TABLE certificates ADD COLUMN IF NOT EXISTS ownership_source TEXT NOT NULL DEFAULT '';
UPDATE certificates SET ownership_source = 'manual' WHERE COALESCE(owner_team,'') <> '';

COMMIT;
