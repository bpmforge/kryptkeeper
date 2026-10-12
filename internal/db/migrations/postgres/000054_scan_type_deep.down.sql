-- Rollback pair of 000054: drop 'deep'. Rewrite any deep rows to 'full'
-- first so the narrower CHECK accepts the existing data.
UPDATE scan_jobs SET type = 'full' WHERE type = 'deep';
ALTER TABLE scan_jobs DROP CONSTRAINT IF EXISTS scan_jobs_type_check;
ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_type_check
    CHECK (type IN ('network', 'ssh', 'winrm', 'cloud_acm', 'cloud_azure_kv',
                     'cloud_gcp_cm', 'kubernetes', 'ct_log', 'agent', 'full',
                     'targeted', 'fast', 'k8s-certmanager'));
