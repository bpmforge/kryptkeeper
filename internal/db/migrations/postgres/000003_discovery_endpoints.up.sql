-- Wave W3 (PostgreSQL)
-- Purpose: discovery + endpoints + mapping
-- Depends on: W2
-- Rollback pair: 000003_discovery_endpoints.down.sql

BEGIN;

CREATE TABLE IF NOT EXISTS scan_jobs (
    id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type                      VARCHAR(30) NOT NULL
                              CHECK (type IN ('network', 'ssh', 'winrm', 'cloud_acm',
                                              'cloud_azure_kv', 'cloud_gcp_cm', 'kubernetes',
                                              'ct_log', 'agent', 'full')),
    connector                 VARCHAR(50) NOT NULL,
    scope                     JSONB NOT NULL DEFAULT '{}',
    status                    VARCHAR(20) NOT NULL DEFAULT 'queued'
                              CHECK (status IN ('queued', 'running', 'complete', 'failed', 'cancelled')),
    error_message             TEXT,
    results_summary           JSONB,
    created_by                UUID REFERENCES users(id),
    started_at                TIMESTAMPTZ,
    completed_at              TIMESTAMPTZ,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS endpoints (
    id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip_address                INET NOT NULL,
    hostname                  VARCHAR(255),
    port                      INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    protocol                  VARCHAR(20) NOT NULL DEFAULT 'tls'
                              CHECK (protocol IN ('tls', 'ldaps', 'imaps', 'smtps', 'pop3s',
                                                   'ftps', 'rdps', 'kubernetes', 'other')),
    tls_versions              TEXT[],
    cipher_suites             TEXT[],
    sni_name                  VARCHAR(255),
    is_default_cert           BOOLEAN NOT NULL DEFAULT TRUE,
    last_scan_job_id          UUID REFERENCES scan_jobs(id),
    last_scanned              TIMESTAMPTZ,
    first_discovered          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tags                      TEXT[],
    created_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scan_results (
    id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_job_id               UUID NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    result_type               VARCHAR(30) NOT NULL
                              CHECK (result_type IN ('certificate', 'endpoint_cert', 'file_cert',
                                                     'error', 'timeout', 'filtered')),
    target                    VARCHAR(512) NOT NULL,
    certificate_fingerprint   VARCHAR(64),
    data                      JSONB NOT NULL DEFAULT '{}',
    error_detail              TEXT,
    discovered_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS certificate_endpoints (
    certificate_fingerprint   VARCHAR(64) NOT NULL
                              REFERENCES certificates(fingerprint_sha256) ON DELETE CASCADE,
    endpoint_id               UUID NOT NULL
                              REFERENCES endpoints(id) ON DELETE CASCADE,
    first_seen                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    currently_active          BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (certificate_fingerprint, endpoint_id)
);

CREATE INDEX IF NOT EXISTS idx_scan_status ON scan_jobs(status);
CREATE INDEX IF NOT EXISTS idx_scan_type ON scan_jobs(type);
CREATE INDEX IF NOT EXISTS idx_scan_created ON scan_jobs(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_endpoint_hostname ON endpoints(hostname);
CREATE INDEX IF NOT EXISTS idx_endpoint_ip ON endpoints(ip_address);
CREATE INDEX IF NOT EXISTS idx_endpoint_last_scanned ON endpoints(last_scanned);
CREATE UNIQUE INDEX IF NOT EXISTS idx_endpoint_unique_network_identity
ON endpoints(ip_address, port, COALESCE(sni_name, ''));

CREATE INDEX IF NOT EXISTS idx_result_scan_job ON scan_results(scan_job_id);
CREATE INDEX IF NOT EXISTS idx_result_fingerprint ON scan_results(certificate_fingerprint);
CREATE INDEX IF NOT EXISTS idx_result_type ON scan_results(result_type);

CREATE INDEX IF NOT EXISTS idx_ce_endpoint ON certificate_endpoints(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_ce_cert ON certificate_endpoints(certificate_fingerprint);
CREATE INDEX IF NOT EXISTS idx_ce_active ON certificate_endpoints(currently_active);

DROP TRIGGER IF EXISTS trg_endpoints_set_updated_at ON endpoints;
CREATE TRIGGER trg_endpoints_set_updated_at
BEFORE UPDATE ON endpoints
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

COMMIT;
