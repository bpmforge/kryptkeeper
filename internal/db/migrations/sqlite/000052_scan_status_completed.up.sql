-- Purpose: align scan_jobs.status's CHECK with the code's canonical
-- terminal spelling 'completed' (G-87/S-23). Every store writes
-- 'completed' (discovery_db_provider.go runAndPersistScan,
-- scannerDiscoveryProvider, discovery_file_provider seeds) and the
-- list handler's whitelist accepts 'completed' — but 000003/000033's
-- CHECK admits only 'complete', so finalizing a finished scan failed
-- with "CHECK constraint failed" and every job sat at 'running'
-- forever. Existing 'complete' rows (000007's seed included) are
-- rewritten to the canonical spelling.
-- SQLite has no ALTER TABLE ... DROP CONSTRAINT, so this uses the
-- rebuild dance on 000033's exact current column list.
-- Depends on: 000033
-- Rollback pair: 000052_scan_status_completed.down.sql

PRAGMA foreign_keys=OFF;

BEGIN;

CREATE TABLE scan_jobs_new (
    id                        TEXT PRIMARY KEY,
    type                      TEXT NOT NULL
                              CHECK (type IN ('network', 'ssh', 'winrm', 'cloud_acm',
                                              'cloud_azure_kv', 'cloud_gcp_cm', 'kubernetes',
                                              'ct_log', 'agent', 'full', 'targeted', 'fast',
                                              'k8s-certmanager')),
    connector                 TEXT NOT NULL,
    scope                     TEXT NOT NULL DEFAULT '{}',
    status                    TEXT NOT NULL DEFAULT 'queued'
                              CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled')),
    error_message             TEXT,
    results_summary           TEXT,
    created_by                TEXT REFERENCES users(id),
    started_at                TEXT,
    completed_at              TEXT,
    created_at                TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
INSERT INTO scan_jobs_new (id, type, connector, scope, status, error_message,
    results_summary, created_by, started_at, completed_at, created_at)
SELECT id, type, connector, scope,
    CASE WHEN status = 'complete' THEN 'completed' ELSE status END,
    error_message,
    results_summary, created_by, started_at, completed_at, created_at FROM scan_jobs;
DROP TABLE scan_jobs;
ALTER TABLE scan_jobs_new RENAME TO scan_jobs;

CREATE INDEX IF NOT EXISTS idx_scan_status ON scan_jobs(status);
CREATE INDEX IF NOT EXISTS idx_scan_type ON scan_jobs(type);
CREATE INDEX IF NOT EXISTS idx_scan_created ON scan_jobs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_status_created ON scan_jobs(status, created_at DESC);

COMMIT;

PRAGMA foreign_keys=ON;
