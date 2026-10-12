DROP INDEX IF EXISTS idx_audit_tenant;
ALTER TABLE audit_log DROP COLUMN tenant;
