-- Rollback of 000360_connector_retry_gate.up.sql
BEGIN;

DROP TABLE IF EXISTS connector_retry_gate;

COMMIT;
