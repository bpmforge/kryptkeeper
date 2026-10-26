-- Rollback of 000361_connector_issue_log.up.sql
BEGIN;

DROP TABLE IF EXISTS connector_issue_log;

COMMIT;
