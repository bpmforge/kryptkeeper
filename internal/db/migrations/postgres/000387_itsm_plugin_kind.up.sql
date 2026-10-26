-- W38-09 (Postgres)
-- Purpose: an ITSM connection may be of kind 'plugin' (a signed ticket plugin, D-326) and names that plugin in
-- plugin_id.
-- Rollback pair: 000387_itsm_plugin_kind.down.sql

BEGIN;

ALTER TABLE itsm_connections ADD COLUMN IF NOT EXISTS plugin_id TEXT NOT NULL DEFAULT '';
ALTER TABLE itsm_connections DROP CONSTRAINT IF EXISTS itsm_connections_kind_check;
ALTER TABLE itsm_connections ADD CONSTRAINT itsm_connections_kind_check CHECK (kind IN ('servicenow','jira','plugin'));

COMMIT;
