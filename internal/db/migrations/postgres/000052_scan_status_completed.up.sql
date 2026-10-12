-- Purpose: align scan_jobs.status's CHECK with the code's canonical
-- terminal spelling 'completed' (G-87/S-23) — see the SQLite pair for
-- the full defect note. IF EXISTS mirrors 000033's defensiveness: a
-- deployment whose scan_jobs came from EnsureSchema declares no CHECK.
-- Depends on: 000033
-- Rollback pair: 000052_scan_status_completed.down.sql

ALTER TABLE scan_jobs DROP CONSTRAINT IF EXISTS scan_jobs_status_check;
UPDATE scan_jobs SET status = 'completed' WHERE status = 'complete';
ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_status_check
    CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled'));
