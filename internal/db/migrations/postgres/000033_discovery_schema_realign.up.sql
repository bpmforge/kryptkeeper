-- Wave S (PostgreSQL)
-- Purpose: realign scan_jobs/endpoints to the TEXT-style ids and
-- hostname/CIDR ip_address values internal/bootstrap/discovery_db_provider.go
-- (the only code that reads/writes these tables) actually generates -- 000003
-- declared scan_jobs.id UUID and endpoints.ip_address INET, and a
-- CHECK(type IN (...)) list missing "targeted"/"fast"/"k8s-certmanager", none
-- of which the provider ever satisfies (G-89). Confirmed by execution against
-- a disposable postgres:16-alpine container: inserting the provider's own
-- string ids/hostnames failed with SQLSTATE 22P02 before this migration.
-- Depends on: 000003
-- Rollback pair: 000033_discovery_schema_realign.down.sql

BEGIN;

-- IF EXISTS on every DROP CONSTRAINT below: a deployment that ran discovery
-- scanning before migrations ever executed has these tables created by
-- discovery_db_provider.go's own bootstrap EnsureSchema (postgresDiscoverySchema),
-- which declares none of 000003's FKs or CHECK constraints -- G-77/S-14's
-- reverse-boot-order scenario, confirmed empirically here too (see this
-- migration's up against a bootstrap-first database in the commit body).
ALTER TABLE certificate_endpoints DROP CONSTRAINT IF EXISTS certificate_endpoints_endpoint_id_fkey;
ALTER TABLE scan_results DROP CONSTRAINT IF EXISTS scan_results_scan_job_id_fkey;
ALTER TABLE endpoints DROP CONSTRAINT IF EXISTS endpoints_last_scan_job_id_fkey;

ALTER TABLE scan_jobs ALTER COLUMN id DROP DEFAULT;
ALTER TABLE scan_jobs ALTER COLUMN id TYPE TEXT USING id::text;

ALTER TABLE endpoints ALTER COLUMN id DROP DEFAULT;
ALTER TABLE endpoints ALTER COLUMN id TYPE TEXT USING id::text;
ALTER TABLE endpoints ALTER COLUMN ip_address TYPE TEXT USING ip_address::text;
ALTER TABLE endpoints ALTER COLUMN last_scan_job_id TYPE TEXT USING last_scan_job_id::text;

ALTER TABLE scan_results ALTER COLUMN scan_job_id TYPE TEXT USING scan_job_id::text;

ALTER TABLE certificate_endpoints ALTER COLUMN endpoint_id TYPE TEXT USING endpoint_id::text;

ALTER TABLE endpoints ADD CONSTRAINT endpoints_last_scan_job_id_fkey
    FOREIGN KEY (last_scan_job_id) REFERENCES scan_jobs(id);
ALTER TABLE scan_results ADD CONSTRAINT scan_results_scan_job_id_fkey
    FOREIGN KEY (scan_job_id) REFERENCES scan_jobs(id) ON DELETE CASCADE;
ALTER TABLE certificate_endpoints ADD CONSTRAINT certificate_endpoints_endpoint_id_fkey
    FOREIGN KEY (endpoint_id) REFERENCES endpoints(id) ON DELETE CASCADE;

-- "targeted"/"fast" are the app's own request-validated scan_type values
-- (handlers_discovery.go); "k8s-certmanager" is the reserved connector-scan
-- type discovery_scanner_provider.go branches on. endpoints.protocol is not
-- touched here: the only DB-persisted protocol value (scanner.go's hardcoded
-- "tls") was already accepted by the existing CHECK.
ALTER TABLE scan_jobs DROP CONSTRAINT IF EXISTS scan_jobs_type_check;
ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_type_check
    CHECK (type IN ('network', 'ssh', 'winrm', 'cloud_acm', 'cloud_azure_kv',
                     'cloud_gcp_cm', 'kubernetes', 'ct_log', 'agent', 'full',
                     'targeted', 'fast', 'k8s-certmanager'));

COMMIT;
