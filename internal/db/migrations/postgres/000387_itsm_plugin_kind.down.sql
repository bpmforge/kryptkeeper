-- W38-09 rollback (Postgres)
-- Purpose: restore the two-kind CHECK and drop plugin_id. Plugin connections would violate it, so they and their
-- ticket links are removed first (the tickets themselves stay in the external system).
-- Pair of: 000387_itsm_plugin_kind.up.sql

BEGIN;

DELETE FROM itsm_events WHERE connection_id IN (SELECT id FROM itsm_connections WHERE kind = 'plugin');
DELETE FROM itsm_connections WHERE kind = 'plugin';
ALTER TABLE itsm_connections DROP CONSTRAINT IF EXISTS itsm_connections_kind_check;
ALTER TABLE itsm_connections ADD CONSTRAINT itsm_connections_kind_check CHECK (kind IN ('servicenow','jira'));
ALTER TABLE itsm_connections DROP COLUMN IF EXISTS plugin_id;

COMMIT;
