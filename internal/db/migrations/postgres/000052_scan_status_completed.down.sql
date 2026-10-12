-- Rollback pair of 000052: restore 000033's 'complete' spelling.

ALTER TABLE scan_jobs DROP CONSTRAINT IF EXISTS scan_jobs_status_check;
UPDATE scan_jobs SET status = 'complete' WHERE status = 'completed';
ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_status_check
    CHECK (status IN ('queued', 'running', 'complete', 'failed', 'cancelled'));
