CREATE TABLE IF NOT EXISTS tenants (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ca_tenants (
    ca_id     TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ca_tenants_tenant ON ca_tenants(tenant_id);
