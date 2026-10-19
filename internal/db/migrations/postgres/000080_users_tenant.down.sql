-- (Postgres) rollback of 000080.
ALTER TABLE users DROP COLUMN IF EXISTS tenant;
