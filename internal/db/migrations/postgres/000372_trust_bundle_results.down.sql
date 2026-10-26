-- Rollback of 000372_trust_bundle_results.up.sql
BEGIN;

DROP TABLE IF EXISTS trust_bundle_results;

COMMIT;
