-- Rollback pair of 000078: map 'completed_with_errors' back to 'completed' and
-- restore 000052's status CHECK.

ALTER TABLE scan_jobs DROP CONSTRAINT IF EXISTS scan_jobs_status_check;
UPDATE scan_jobs SET status = 'completed' WHERE status = 'completed_with_errors';
ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_status_check
    CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled'));
