-- Wave S rollback (PostgreSQL)
-- Paired with: 000033_discovery_schema_realign.up.sql
--
-- Reverses cleanly only against data that fits the original UUID/INET
-- shape (i.e. rolled back before real string ids/hostnames are written) --
-- the same assumption every other down.sql in this tree makes.

BEGIN;

ALTER TABLE scan_jobs DROP CONSTRAINT scan_jobs_type_check;
ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_type_check
    CHECK (type IN ('network', 'ssh', 'winrm', 'cloud_acm', 'cloud_azure_kv',
                     'cloud_gcp_cm', 'kubernetes', 'ct_log', 'agent', 'full'));

ALTER TABLE certificate_endpoints DROP CONSTRAINT certificate_endpoints_endpoint_id_fkey;
ALTER TABLE scan_results DROP CONSTRAINT scan_results_scan_job_id_fkey;
ALTER TABLE endpoints DROP CONSTRAINT endpoints_last_scan_job_id_fkey;

ALTER TABLE certificate_endpoints ALTER COLUMN endpoint_id TYPE UUID USING endpoint_id::uuid;
ALTER TABLE scan_results ALTER COLUMN scan_job_id TYPE UUID USING scan_job_id::uuid;

ALTER TABLE endpoints ALTER COLUMN last_scan_job_id TYPE UUID USING last_scan_job_id::uuid;
ALTER TABLE endpoints ALTER COLUMN ip_address TYPE INET USING ip_address::inet;
ALTER TABLE endpoints ALTER COLUMN id TYPE UUID USING id::uuid;
ALTER TABLE endpoints ALTER COLUMN id SET DEFAULT gen_random_uuid();

ALTER TABLE scan_jobs ALTER COLUMN id TYPE UUID USING id::uuid;
ALTER TABLE scan_jobs ALTER COLUMN id SET DEFAULT gen_random_uuid();

ALTER TABLE endpoints ADD CONSTRAINT endpoints_last_scan_job_id_fkey
    FOREIGN KEY (last_scan_job_id) REFERENCES scan_jobs(id);
ALTER TABLE scan_results ADD CONSTRAINT scan_results_scan_job_id_fkey
    FOREIGN KEY (scan_job_id) REFERENCES scan_jobs(id) ON DELETE CASCADE;
ALTER TABLE certificate_endpoints ADD CONSTRAINT certificate_endpoints_endpoint_id_fkey
    FOREIGN KEY (endpoint_id) REFERENCES endpoints(id) ON DELETE CASCADE;

COMMIT;
