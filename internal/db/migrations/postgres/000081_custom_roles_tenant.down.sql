DROP INDEX IF EXISTS idx_custom_roles_tenant;
ALTER TABLE custom_roles DROP COLUMN tenant_id;
