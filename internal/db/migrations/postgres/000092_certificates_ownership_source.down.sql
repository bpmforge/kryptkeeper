-- W22-24 (PostgreSQL) rollback

BEGIN;

ALTER TABLE certificates DROP COLUMN IF EXISTS ownership_source;

COMMIT;
