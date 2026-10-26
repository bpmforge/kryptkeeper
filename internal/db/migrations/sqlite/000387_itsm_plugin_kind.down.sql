-- W38-09 rollback (SQLite)
-- Purpose: restore the two-kind CHECK and drop plugin_id. Plugin connections would violate it, so they and their
-- ticket links are removed first (the tickets themselves stay in the external system).
-- Pair of: 000387_itsm_plugin_kind.up.sql

PRAGMA foreign_keys=OFF;

BEGIN;

DELETE FROM itsm_events WHERE connection_id IN (SELECT id FROM itsm_connections WHERE kind = 'plugin');
DELETE FROM itsm_connections WHERE kind = 'plugin';

CREATE TABLE itsm_connections_new (
    id             TEXT PRIMARY KEY,
    kind           TEXT NOT NULL CHECK (kind IN ('servicenow','jira')),
    name           TEXT NOT NULL,
    base_url       TEXT NOT NULL,
    credential_ref TEXT NOT NULL,
    event_classes  TEXT NOT NULL DEFAULT '[]',
    enabled        INTEGER NOT NULL DEFAULT 1,
    tenant         TEXT NOT NULL DEFAULT 'default',
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);
INSERT INTO itsm_connections_new (id, kind, name, base_url, credential_ref, event_classes, enabled, tenant, created_at, updated_at)
SELECT id, kind, name, base_url, credential_ref, event_classes, enabled, tenant, created_at, updated_at FROM itsm_connections;
DROP TABLE itsm_connections;
ALTER TABLE itsm_connections_new RENAME TO itsm_connections;

COMMIT;

PRAGMA foreign_keys=ON;
