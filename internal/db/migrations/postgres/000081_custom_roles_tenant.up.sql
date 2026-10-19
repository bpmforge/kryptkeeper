-- W22-01 (L-19): custom roles carry a tenant. Empty string = GLOBAL role, so
-- every pre-existing row stays global and keeps today's behaviour.
ALTER TABLE custom_roles ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_custom_roles_tenant ON custom_roles(tenant_id);
