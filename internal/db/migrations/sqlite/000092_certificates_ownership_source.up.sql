-- W22-24: where a certificate's owner assignment came from
-- (manual|cmdb|import|agent). '' = unowned. Semantics identical to postgres.
ALTER TABLE certificates ADD COLUMN ownership_source TEXT NOT NULL DEFAULT '';
UPDATE certificates SET ownership_source = 'manual' WHERE COALESCE(owner_team,'') <> '';
