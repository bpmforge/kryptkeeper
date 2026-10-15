-- (PostgreSQL) rollback of 000077.
ALTER TABLE certificates DROP COLUMN IF EXISTS is_ca;
ALTER TABLE certificates DROP COLUMN IF EXISTS trust_class;
