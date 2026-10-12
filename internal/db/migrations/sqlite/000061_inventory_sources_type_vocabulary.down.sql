-- Rows of the newer types cannot satisfy the narrower CHECK; drop them.
DELETE FROM inventory_sources WHERE type NOT IN ('adcs_export', 'digicert');
DROP TABLE IF EXISTS inventory_sources_old;
CREATE TABLE inventory_sources_old (
    id               TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    type             TEXT NOT NULL CHECK (type IN ('adcs_export', 'digicert')),
    config_json      TEXT NOT NULL DEFAULT '{}',
    credential_ref   TEXT,
    schedule_minutes INTEGER NOT NULL DEFAULT 0
                     CHECK (schedule_minutes >= 0),
    tenant           TEXT NOT NULL DEFAULT 'default',
    last_sync_at     TEXT,
    last_sync_result TEXT,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL
);
INSERT INTO inventory_sources_old (id, name, type, config_json, credential_ref, schedule_minutes, tenant, last_sync_at, last_sync_result, created_at, updated_at) SELECT id, name, type, config_json, credential_ref, schedule_minutes, tenant, last_sync_at, last_sync_result, created_at, updated_at FROM inventory_sources;
DROP TABLE inventory_sources;
ALTER TABLE inventory_sources_old RENAME TO inventory_sources;
CREATE INDEX IF NOT EXISTS idx_inventory_sources_tenant ON inventory_sources(tenant);
