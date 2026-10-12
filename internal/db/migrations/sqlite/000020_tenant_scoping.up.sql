CREATE TABLE IF NOT EXISTS template_tenants (template_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_template_tenants_tenant ON template_tenants(tenant_id);
ALTER TABLE pending_actions ADD COLUMN tenant TEXT NOT NULL DEFAULT 'default';
