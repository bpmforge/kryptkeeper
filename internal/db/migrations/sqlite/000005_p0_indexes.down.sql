-- Wave W5 rollback (SQLite)
-- Paired with: 000005_p0_indexes.up.sql

BEGIN;

DROP INDEX IF EXISTS idx_audit_outcome_ts;
DROP INDEX IF EXISTS idx_ce_endpoint_active;
DROP INDEX IF EXISTS idx_scan_results_scan_job_cert;
DROP INDEX IF EXISTS idx_scan_status_created;
DROP INDEX IF EXISTS idx_cert_revoked_at;

COMMIT;
