-- Rollback pair of 000058. Reverses cleanly only against data that fits the
-- original, narrower CHECKs (the same assumption every other down.sql in
-- this tree makes) -- any port=0 or mesh-protocol row written since 000058
-- landed is deleted first (cascades to certificate_endpoints) since it has
-- no valid representation under the pre-W19-22 schema.

PRAGMA foreign_keys=OFF;

BEGIN;

DELETE FROM endpoints WHERE port = 0 OR protocol IN ('k8s-tls-secret', 'istio-mesh', 'linkerd-mesh');

CREATE TABLE endpoints_new (
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
    updated_at                TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    server_tech               TEXT,
    recommended_install_mode  TEXT,
    ssh_banner                TEXT,
    ssh_host_key_algorithms   TEXT,
    crypto_posture            TEXT
);

INSERT INTO endpoints_new (id, ip_address, hostname, port, protocol, tls_versions,
    cipher_suites, sni_name, is_default_cert, last_scan_job_id, last_scanned,
    first_discovered, tags, created_at, updated_at, server_tech,
    recommended_install_mode, ssh_banner, ssh_host_key_algorithms, crypto_posture)
SELECT id, ip_address, hostname, port, protocol, tls_versions,
    cipher_suites, sni_name, is_default_cert, last_scan_job_id, last_scanned,
    first_discovered, tags, created_at, updated_at, server_tech,
    recommended_install_mode, ssh_banner, ssh_host_key_algorithms, crypto_posture
FROM endpoints;

DROP TABLE endpoints;
ALTER TABLE endpoints_new RENAME TO endpoints;

CREATE INDEX IF NOT EXISTS idx_endpoint_hostname ON endpoints(hostname);
CREATE INDEX IF NOT EXISTS idx_endpoint_ip ON endpoints(ip_address);
CREATE INDEX IF NOT EXISTS idx_endpoint_last_scanned ON endpoints(last_scanned);
CREATE UNIQUE INDEX IF NOT EXISTS idx_endpoint_unique_network_identity
ON endpoints(ip_address, port, IFNULL(sni_name, ''));

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
