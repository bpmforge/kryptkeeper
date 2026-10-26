-- Rollback of 000371_trust_bundles.up.sql
BEGIN;

DROP TABLE IF EXISTS trust_bundles;

COMMIT;
