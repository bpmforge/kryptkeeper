-- Rollback pair of 000340. Rows using a protocol added by 000340 are recorded
-- as 'other' (what they were before the vocabulary grew) rather than deleted;
-- the five fingerprint columns go with the rebuilt table. `issues` is not
-- carried, for the reason given in the up migration.

PRAGMA foreign_keys=OFF;

BEGIN;

CREATE TABLE endpoints_new (
    id                        TEXT PRIMARY KEY,
    ip_address                TEXT NOT NULL,
    hostname                  TEXT,
    port                      INTEGER NOT NULL CHECK (port BETWEEN 0 AND 65535),
    protocol                  TEXT NOT NULL DEFAULT 'tls'
                              CHECK (protocol IN ('tls', 'ldaps', 'imaps', 'smtps', 'pop3s',
                                                   'ftps', 'rdps', 'kubernetes', 'other',
                                                   'k8s-tls-secret', 'istio-mesh', 'linkerd-mesh')),
    tls_versions              TEXT,
    cipher_suites             TEXT,
    sni_name                  TEXT,
    is_default_cert           INTEGER NOT NULL DEFAULT 1 CHECK (is_default_cert IN (0,1)),
    last_scan_job_id          TEXT REFERENCES scan_jobs(id),
    last_scanned              TEXT,
    first_discovered          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    tags                      TEXT,
    created_at                TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at                TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    server_tech               TEXT,
    recommended_install_mode  TEXT,
    ssh_banner                TEXT,
    ssh_host_key_algorithms   TEXT,
    crypto_posture            TEXT,
    tenant                    TEXT NOT NULL DEFAULT ''
);

INSERT INTO endpoints_new (id, ip_address, hostname, port, protocol, tls_versions,
    cipher_suites, sni_name, is_default_cert, last_scan_job_id, last_scanned,
    first_discovered, tags, created_at, updated_at, server_tech,
    recommended_install_mode, ssh_banner, ssh_host_key_algorithms, crypto_posture, tenant)
SELECT id, ip_address, hostname, port,
    CASE WHEN protocol IN ('mssql', 'mysql', 'oracle', 'redis', 'mongodb', 'kafka') THEN 'other' ELSE protocol END,
    tls_versions,
    cipher_suites, sni_name, is_default_cert, last_scan_job_id, last_scanned,
    first_discovered, tags, created_at, updated_at, server_tech,
    recommended_install_mode, ssh_banner, ssh_host_key_algorithms, crypto_posture, tenant
FROM endpoints;

DROP TABLE endpoints;
ALTER TABLE endpoints_new RENAME TO endpoints;

CREATE INDEX IF NOT EXISTS idx_endpoint_hostname ON endpoints(hostname);
CREATE INDEX IF NOT EXISTS idx_endpoint_ip ON endpoints(ip_address);
CREATE INDEX IF NOT EXISTS idx_endpoint_last_scanned ON endpoints(last_scanned);
CREATE UNIQUE INDEX IF NOT EXISTS idx_endpoint_unique_identity_tenant ON endpoints(tenant, ip_address, port, sni_name);

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

PRAGMA foreign_keys=ON;
