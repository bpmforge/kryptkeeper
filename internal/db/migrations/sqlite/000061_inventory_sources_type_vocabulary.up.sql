-- Widen inventory_sources.type to every type validInventorySourceTypes
-- accepts (internal/bootstrap/inventory_source.go). 000045 only allowed
-- 'adcs_export' and 'digicert', so creating an adcs_live, sectigo, entrust,
-- aws_pca or gcp_cas source passed the handler's validation and then failed
-- the CHECK, surfacing as a 503 "create failed". Found by the W19-06 AD LDAP
-- fixture running against a real Samba DC; unit tests use an in-memory fake
-- store with no CHECK.
-- SQLite cannot alter a CHECK, so rebuild the table (no FKs reference it).
-- Depends on: 000045
-- Rollback pair: 000061_inventory_sources_type_vocabulary.down.sql
DROP TABLE IF EXISTS inventory_sources_new;
CREATE TABLE inventory_sources_new (
    id               TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    type             TEXT NOT NULL CHECK (type IN ('adcs_export', 'adcs_live', 'digicert', 'sectigo', 'entrust', 'aws_pca', 'gcp_cas')),
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
INSERT INTO inventory_sources_new (id, name, type, config_json, credential_ref, schedule_minutes, tenant, last_sync_at, last_sync_result, created_at, updated_at) SELECT id, name, type, config_json, credential_ref, schedule_minutes, tenant, last_sync_at, last_sync_result, created_at, updated_at FROM inventory_sources;
DROP TABLE inventory_sources;
ALTER TABLE inventory_sources_new RENAME TO inventory_sources;
CREATE INDEX IF NOT EXISTS idx_inventory_sources_tenant ON inventory_sources(tenant);
