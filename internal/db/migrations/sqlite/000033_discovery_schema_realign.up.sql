-- Wave S (SQLite)
-- Purpose: widen scan_jobs.type's CHECK constraint to accept the app's real
-- "targeted"/"fast" request-validated scan types (handlers_discovery.go) and
-- the "k8s-certmanager" reserved connector-scan type
-- (discovery_scanner_provider.go) (G-89). Confirmed empirically: SQLite
-- enforces CHECK constraints exactly like Postgres, so despite scan_jobs.id/
-- endpoints.ip_address already being TEXT here (the id/INET half of G-89 is
-- Postgres-only), this same-named CHECK list is a real, narrower gap on this
-- engine too -- inserting type='targeted' or 'k8s-certmanager' fails with
-- "CHECK constraint failed" before this migration. endpoints is untouched:
-- its columns/CHECK already accept every value the app writes.
-- SQLite has no ALTER TABLE ... DROP CONSTRAINT, so this uses the standard
-- rebuild dance (000025_principal_tenant's pattern).
-- Depends on: 000003 (+000005_p0_indexes' idx_scan_status_created)
-- Rollback pair: 000033_discovery_schema_realign.down.sql

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
                              CHECK (status IN ('queued', 'running', 'complete', 'failed', 'cancelled')),
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
