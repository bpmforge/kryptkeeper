-- Wave W5 (PostgreSQL)
-- Purpose: P0 query indexes
-- Depends on: W2, W3, W4
-- Rollback pair: 000005_p0_indexes.down.sql

BEGIN;

-- Certificates hot paths
CREATE INDEX IF NOT EXISTS idx_cert_revoked_at ON certificates(revoked_at);

-- Discovery operational hot paths
CREATE INDEX IF NOT EXISTS idx_scan_status_created ON scan_jobs(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_results_scan_job_cert
    ON scan_results(scan_job_id, certificate_fingerprint);

-- Endpoint mapping hot paths
CREATE INDEX IF NOT EXISTS idx_ce_endpoint_active ON certificate_endpoints(endpoint_id, currently_active);

-- Audit drilldown backup paths (partitioned indexes created on parent)
CREATE INDEX IF NOT EXISTS idx_audit_outcome_ts ON audit_log(outcome, timestamp DESC);

COMMIT;
