-- W22-29 (PostgreSQL) rollback

BEGIN;

DROP TABLE IF EXISTS finding_identities;

COMMIT;
