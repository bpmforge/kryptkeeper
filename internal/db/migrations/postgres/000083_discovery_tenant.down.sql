-- (Postgres) rollback of 000083. Restoring the tenant-blind unique index fails if
-- two tenants have scanned the same address; collapse those rows first.
DROP INDEX IF EXISTS idx_endpoint_unique_identity_tenant;
CREATE UNIQUE INDEX IF NOT EXISTS idx_endpoint_unique_network_identity ON endpoints(ip_address, port, COALESCE(sni_name, ''));
ALTER TABLE endpoints DROP COLUMN IF EXISTS tenant;
ALTER TABLE scan_jobs DROP COLUMN IF EXISTS tenant;
