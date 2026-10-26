-- W38-09 (SQLite)
-- Purpose: an ITSM connection may be of kind 'plugin' (a signed ticket plugin, D-326) and names that plugin in
-- plugin_id. SQLite cannot alter a CHECK, so itsm_connections is rebuilt (000302 pattern) keeping every row;
-- itsm_events references it by name and is untouched.
-- Rollback pair: 000387_itsm_plugin_kind.down.sql

PRAGMA foreign_keys=OFF;

BEGIN;

CREATE TABLE itsm_connections_new (
    id             TEXT PRIMARY KEY,
    kind           TEXT NOT NULL CHECK (kind IN ('servicenow','jira','plugin')),
    name           TEXT NOT NULL,
    base_url       TEXT NOT NULL,
    credential_ref TEXT NOT NULL,
    plugin_id      TEXT NOT NULL DEFAULT '',
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
