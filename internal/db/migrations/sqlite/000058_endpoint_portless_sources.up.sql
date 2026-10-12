-- Purpose: allow port-less discovery endpoints to persist -- see the
-- Postgres pair (000058_endpoint_portless_sources.up.sql) for the full
-- defect writeup (W19-22, found live on W19-09's kind UAT, 2026-09-11).
-- Port=0 now means "not a network listener" (K8s-secret-sourced mesh
-- sources -- Istio/Linkerd -- identified by a K8s object name, not an
-- address); the protocol CHECK is widened in the same migration to record
-- the source kind honestly (k8s-tls-secret/istio-mesh/linkerd-mesh, the
-- exact tags internal/discovery/servicemesh.go already emits) instead of
-- collapsing it to 'other'.
--
-- SQLite has no ALTER TABLE ... DROP CONSTRAINT, so this uses the standard
-- rebuild dance (000025_principal_tenant's pattern, most recently used by
-- 000033 for this table's sibling scan_jobs). The rebuilt table carries
-- every column a VERSIONED migration has ever added to endpoints (000003,
-- 000053, 000055, 000056); it deliberately does NOT carry `issues` --
-- that column only ever existed via discovery_db_provider.go's best-effort
-- `ALTER TABLE endpoints ADD COLUMN issues ...` in EnsureSchema, never a
-- numbered migration, so a fresh (migrations-only, EnsureSchema-never-run)
-- database has no such column to copy from. EnsureSchema re-adds it after
-- this migration runs (a plain ADD COLUMN, no rebuild needed) on every
-- deployment where it existed before; the practical cost is a cache of
-- already-computed cipheraudit findings reset to '[]' until the next scan
-- repopulates it -- advisory, recomputed every sweep, never source-of-truth
-- cert material.
-- Depends on: 000056 (last versioned column addition to endpoints)
-- Rollback pair: 000058_endpoint_portless_sources.down.sql

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
