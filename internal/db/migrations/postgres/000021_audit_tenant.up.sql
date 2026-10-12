-- Wave W2 (PostgreSQL)
-- Purpose: record the tenant context an audited action ran under (W2-04)
-- Depends on: W4 (audit_log)
-- Rollback pair: 000021_audit_tenant.down.sql

BEGIN;

ALTER TABLE audit_log ADD COLUMN tenant TEXT NOT NULL DEFAULT 'default';

CREATE INDEX idx_audit_tenant ON audit_log(tenant);

COMMIT;
