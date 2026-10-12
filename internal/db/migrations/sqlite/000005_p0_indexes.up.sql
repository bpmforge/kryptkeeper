-- Wave W5 (SQLite)
-- Purpose: P0 query indexes
-- Depends on: W2, W3, W4
-- Rollback pair: 000005_p0_indexes.down.sql

BEGIN;

CREATE INDEX IF NOT EXISTS idx_cert_revoked_at ON certificates(revoked_at);
CREATE INDEX IF NOT EXISTS idx_scan_status_created ON scan_jobs(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_results_scan_job_cert
    ON scan_results(scan_job_id, certificate_fingerprint);
CREATE INDEX IF NOT EXISTS idx_ce_endpoint_active ON certificate_endpoints(endpoint_id, currently_active);
CREATE INDEX IF NOT EXISTS idx_audit_outcome_ts ON audit_log(outcome, timestamp DESC);

COMMIT;
