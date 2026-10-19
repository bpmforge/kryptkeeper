-- Rollback pair: 000086_audit_archives.up.sql
DROP INDEX IF EXISTS idx_audit_archives_chain_head;
DROP TABLE IF EXISTS audit_archives;
