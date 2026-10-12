-- Wave W11 (PostgreSQL)
-- Purpose: Add security fields to audit_log for SOC 2 / PCI DSS / FedRAMP compliance
-- Depends on: W4
-- Rollback pair: 000011_audit_log_security_fields.down.sql

BEGIN;

ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS source_ip    TEXT;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS user_agent   TEXT;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS session_id   TEXT;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS change_summary TEXT;

CREATE INDEX IF NOT EXISTS idx_audit_source_ip ON audit_log(source_ip) WHERE source_ip IS NOT NULL;

COMMIT;
