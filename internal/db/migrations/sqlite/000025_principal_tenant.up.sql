-- Wave W3 (SQLite)
-- Purpose: FK ca_tenants/template_tenants -> tenants (W3-01 acceptance #3)
-- Depends on: W2 (tenants, ca_tenants, template_tenants)
-- Rollback pair: 000025_principal_tenant.down.sql
--
-- SQLite has no ALTER TABLE ADD CONSTRAINT; adding a FK to an existing table
-- requires the standard rebuild dance (new table with the constraint, copy,
-- drop, rename). Requires PRAGMA foreign_keys=OFF for the duration (already
-- off inside a single connection unless _fk=1 is set, but disabled here
-- explicitly for migration-runner safety).

PRAGMA foreign_keys=OFF;

BEGIN;

CREATE TABLE ca_tenants_new (
    ca_id     TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id)
);
INSERT INTO ca_tenants_new (ca_id, tenant_id) SELECT ca_id, tenant_id FROM ca_tenants;
DROP TABLE ca_tenants;
ALTER TABLE ca_tenants_new RENAME TO ca_tenants;
CREATE INDEX IF NOT EXISTS idx_ca_tenants_tenant ON ca_tenants(tenant_id);

CREATE TABLE template_tenants_new (
    template_id TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(id)
);
INSERT INTO template_tenants_new (template_id, tenant_id) SELECT template_id, tenant_id FROM template_tenants;
DROP TABLE template_tenants;
ALTER TABLE template_tenants_new RENAME TO template_tenants;
CREATE INDEX IF NOT EXISTS idx_template_tenants_tenant ON template_tenants(tenant_id);

COMMIT;

PRAGMA foreign_keys=ON;
