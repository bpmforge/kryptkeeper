PRAGMA foreign_keys=OFF;

BEGIN;

CREATE TABLE ca_tenants_new (
    ca_id     TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL
);
INSERT INTO ca_tenants_new (ca_id, tenant_id) SELECT ca_id, tenant_id FROM ca_tenants;
DROP TABLE ca_tenants;
ALTER TABLE ca_tenants_new RENAME TO ca_tenants;
CREATE INDEX IF NOT EXISTS idx_ca_tenants_tenant ON ca_tenants(tenant_id);

CREATE TABLE template_tenants_new (
    template_id TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL
);
INSERT INTO template_tenants_new (template_id, tenant_id) SELECT template_id, tenant_id FROM template_tenants;
DROP TABLE template_tenants;
ALTER TABLE template_tenants_new RENAME TO template_tenants;
CREATE INDEX IF NOT EXISTS idx_template_tenants_tenant ON template_tenants(tenant_id);

COMMIT;

PRAGMA foreign_keys=ON;
