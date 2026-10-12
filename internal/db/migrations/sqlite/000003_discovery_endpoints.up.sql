-- Wave W3 (SQLite)
-- Purpose: discovery + endpoints + mapping
-- Depends on: W2
-- Rollback pair: 000003_discovery_endpoints.down.sql

BEGIN;

CREATE TABLE IF NOT EXISTS scan_jobs (
    id                        TEXT PRIMARY KEY,
    type                      TEXT NOT NULL
                              CHECK (type IN ('network', 'ssh', 'winrm', 'cloud_acm',
                                              'cloud_azure_kv', 'cloud_gcp_cm', 'kubernetes',
                                              'ct_log', 'agent', 'full')),
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

CREATE TABLE IF NOT EXISTS endpoints (
    id                        TEXT PRIMARY KEY,
    ip_address                TEXT NOT NULL,
    hostname                  TEXT,
    port                      INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    protocol                  TEXT NOT NULL DEFAULT 'tls'
                              CHECK (protocol IN ('tls', 'ldaps', 'imaps', 'smtps', 'pop3s',
                                                   'ftps', 'rdps', 'kubernetes', 'other')),
    tls_versions              TEXT,
    cipher_suites             TEXT,
    sni_name                  TEXT,
    is_default_cert           INTEGER NOT NULL DEFAULT 1 CHECK (is_default_cert IN (0,1)),
    last_scan_job_id          TEXT REFERENCES scan_jobs(id),
    last_scanned              TEXT,
    first_discovered          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    tags                      TEXT,
    created_at                TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at                TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS scan_results (
    id                        TEXT PRIMARY KEY,
    scan_job_id               TEXT NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    result_type               TEXT NOT NULL
                              CHECK (result_type IN ('certificate', 'endpoint_cert', 'file_cert',
                                                     'error', 'timeout', 'filtered')),
    target                    TEXT NOT NULL,
    certificate_fingerprint   TEXT,
    data                      TEXT NOT NULL DEFAULT '{}',
    error_detail              TEXT,
    discovered_at             TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS certificate_endpoints (
    certificate_fingerprint   TEXT NOT NULL
                              REFERENCES certificates(fingerprint_sha256) ON DELETE CASCADE,
    endpoint_id               TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
    first_seen                TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    last_seen                 TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    currently_active          INTEGER NOT NULL DEFAULT 1 CHECK (currently_active IN (0,1)),
    PRIMARY KEY (certificate_fingerprint, endpoint_id)
);

CREATE INDEX IF NOT EXISTS idx_scan_status ON scan_jobs(status);
CREATE INDEX IF NOT EXISTS idx_scan_type ON scan_jobs(type);
CREATE INDEX IF NOT EXISTS idx_scan_created ON scan_jobs(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_endpoint_hostname ON endpoints(hostname);
CREATE INDEX IF NOT EXISTS idx_endpoint_ip ON endpoints(ip_address);
CREATE INDEX IF NOT EXISTS idx_endpoint_last_scanned ON endpoints(last_scanned);
CREATE UNIQUE INDEX IF NOT EXISTS idx_endpoint_unique_network_identity
ON endpoints(ip_address, port, IFNULL(sni_name, ''));

CREATE INDEX IF NOT EXISTS idx_result_scan_job ON scan_results(scan_job_id);
CREATE INDEX IF NOT EXISTS idx_result_fingerprint ON scan_results(certificate_fingerprint);
CREATE INDEX IF NOT EXISTS idx_result_type ON scan_results(result_type);

CREATE INDEX IF NOT EXISTS idx_ce_endpoint ON certificate_endpoints(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_ce_cert ON certificate_endpoints(certificate_fingerprint);
CREATE INDEX IF NOT EXISTS idx_ce_active ON certificate_endpoints(currently_active);

CREATE TRIGGER IF NOT EXISTS trg_endpoints_set_updated_at
AFTER UPDATE ON endpoints
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE endpoints
       SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
     WHERE id = NEW.id;
END;

COMMIT;
