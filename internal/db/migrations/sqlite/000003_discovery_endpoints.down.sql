-- Wave W3 rollback (SQLite)
-- Paired with: 000003_discovery_endpoints.up.sql

BEGIN;

DROP TRIGGER IF EXISTS trg_endpoints_set_updated_at;

DROP INDEX IF EXISTS idx_ce_active;
DROP INDEX IF EXISTS idx_ce_cert;
DROP INDEX IF EXISTS idx_ce_endpoint;
DROP INDEX IF EXISTS idx_result_type;
DROP INDEX IF EXISTS idx_result_fingerprint;
DROP INDEX IF EXISTS idx_result_scan_job;
DROP INDEX IF EXISTS idx_endpoint_unique_network_identity;
DROP INDEX IF EXISTS idx_endpoint_last_scanned;
DROP INDEX IF EXISTS idx_endpoint_ip;
DROP INDEX IF EXISTS idx_endpoint_hostname;
DROP INDEX IF EXISTS idx_scan_created;
DROP INDEX IF EXISTS idx_scan_type;
DROP INDEX IF EXISTS idx_scan_status;

DROP TABLE IF EXISTS certificate_endpoints;
DROP TABLE IF EXISTS scan_results;
DROP TABLE IF EXISTS endpoints;
DROP TABLE IF EXISTS scan_jobs;

COMMIT;
