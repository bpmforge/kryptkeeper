-- Wave W12 (PostgreSQL) - rollback

BEGIN;

ALTER TABLE certificates DROP COLUMN IF EXISTS owner_email;
ALTER TABLE certificates DROP COLUMN IF EXISTS owner_team;
ALTER TABLE certificates DROP COLUMN IF EXISTS service_name;
ALTER TABLE certificates DROP COLUMN IF EXISTS labels;

COMMIT;
