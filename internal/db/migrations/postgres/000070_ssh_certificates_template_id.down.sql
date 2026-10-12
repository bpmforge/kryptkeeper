-- Rollback of 000070 (PostgreSQL).

BEGIN;

ALTER TABLE ssh_certificates DROP COLUMN IF EXISTS template_id;

COMMIT;
