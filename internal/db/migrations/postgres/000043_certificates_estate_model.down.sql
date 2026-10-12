BEGIN;

ALTER TABLE certificates DROP COLUMN origin;
ALTER TABLE certificates DROP COLUMN management_state;

COMMIT;
