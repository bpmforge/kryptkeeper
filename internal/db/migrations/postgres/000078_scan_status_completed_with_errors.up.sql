-- Purpose: admit scan_jobs.status 'completed_with_errors' — see the SQLite
-- pair for the defect note. IF EXISTS mirrors 000052: a deployment whose
-- scan_jobs came from EnsureSchema declares no CHECK.
-- Depends on: 000052
-- Rollback pair: 000078_scan_status_completed_with_errors.down.sql

ALTER TABLE scan_jobs DROP CONSTRAINT IF EXISTS scan_jobs_status_check;
ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_status_check
    CHECK (status IN ('queued', 'running', 'completed', 'completed_with_errors', 'failed', 'cancelled'));
