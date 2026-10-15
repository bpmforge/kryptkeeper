-- Purpose: admit scan_jobs.status 'completed_with_errors' — a scan that ran
-- but found hosts that answered and failed (plain HTTP on a TLS port, a
-- failed handshake). Those used to be dropped and the job reported plain
-- "completed". 000052's CHECK listed only queued|running|completed|failed|
-- cancelled, so finalizing such a job would fail with "CHECK constraint
-- failed" and leave it 'running'.
-- SQLite has no ALTER TABLE ... DROP CONSTRAINT, so this uses the rebuild
-- dance on 000054's exact current column list.
-- Depends on: 000054
-- Rollback pair: 000078_scan_status_completed_with_errors.down.sql

PRAGMA foreign_keys=OFF;

BEGIN;

CREATE TABLE scan_jobs_new (
    id                        TEXT PRIMARY KEY,
    type                      TEXT NOT NULL
                              CHECK (type IN ('network', 'ssh', 'winrm', 'cloud_acm',
                                              'cloud_azure_kv', 'cloud_gcp_cm', 'kubernetes',
                                              'ct_log', 'agent', 'full', 'targeted', 'fast',
                                              'deep', 'k8s-certmanager')),
    connector                 TEXT NOT NULL,
    scope                     TEXT NOT NULL DEFAULT '{}',
    status                    TEXT NOT NULL DEFAULT 'queued'
                              CHECK (status IN ('queued', 'running', 'completed', 'completed_with_errors',
                                                'failed', 'cancelled')),
    error_message             TEXT,
    results_summary           TEXT,
    created_by                TEXT REFERENCES users(id),
    started_at                TEXT,
    completed_at              TEXT,
    created_at                TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
INSERT INTO scan_jobs_new (id, type, connector, scope, status, error_message,
    results_summary, created_by, started_at, completed_at, created_at)
SELECT id, type, connector, scope, status, error_message,
    results_summary, created_by, started_at, completed_at, created_at FROM scan_jobs;
DROP TABLE scan_jobs;
ALTER TABLE scan_jobs_new RENAME TO scan_jobs;

CREATE INDEX IF NOT EXISTS idx_scan_status ON scan_jobs(status);
CREATE INDEX IF NOT EXISTS idx_scan_type ON scan_jobs(type);
CREATE INDEX IF NOT EXISTS idx_scan_created ON scan_jobs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_status_created ON scan_jobs(status, created_at DESC);

COMMIT;

PRAGMA foreign_keys=ON;
