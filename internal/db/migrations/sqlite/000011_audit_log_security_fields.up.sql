-- Wave W11 (SQLite)
-- Purpose: Add security fields to audit_log for SOC 2 / PCI DSS / FedRAMP compliance
-- Depends on: W4
-- Rollback pair: 000011_audit_log_security_fields.down.sql

BEGIN;

ALTER TABLE audit_log ADD COLUMN source_ip TEXT;
ALTER TABLE audit_log ADD COLUMN user_agent TEXT;
ALTER TABLE audit_log ADD COLUMN session_id TEXT;
ALTER TABLE audit_log ADD COLUMN change_summary TEXT;

COMMIT;
