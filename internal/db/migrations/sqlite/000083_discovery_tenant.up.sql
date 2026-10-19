-- (sqlite) Discovery scan jobs and endpoints belong to a tenant. '' means
-- DefaultTenant, so existing rows stay in the default tenant. The endpoint
-- identity becomes per-tenant so two tenants scanning one address each keep
-- their own row.
ALTER TABLE scan_jobs ADD COLUMN tenant TEXT NOT NULL DEFAULT '';
ALTER TABLE endpoints ADD COLUMN tenant TEXT NOT NULL DEFAULT '';
DROP INDEX IF EXISTS idx_endpoint_unique_identity;
DROP INDEX IF EXISTS idx_endpoint_unique_network_identity;
CREATE UNIQUE INDEX IF NOT EXISTS idx_endpoint_unique_identity_tenant ON endpoints(tenant, ip_address, port, sni_name);
