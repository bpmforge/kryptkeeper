-- Purpose: admit scan_jobs.type 'deep' — the full TCP-connect port-sweep
-- scan mode. See the SQLite pair for the defect note.
-- Depends on: 000052
-- Rollback pair: 000054_scan_type_deep.down.sql

ALTER TABLE scan_jobs DROP CONSTRAINT IF EXISTS scan_jobs_type_check;
ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_type_check
    CHECK (type IN ('network', 'ssh', 'winrm', 'cloud_acm', 'cloud_azure_kv',
                     'cloud_gcp_cm', 'kubernetes', 'ct_log', 'agent', 'full',
                     'targeted', 'fast', 'deep', 'k8s-certmanager'));
