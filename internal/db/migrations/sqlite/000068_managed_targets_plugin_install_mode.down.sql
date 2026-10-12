-- Rollback of 000068 (SQLite): back to 000065's columns and install modes.
-- Plugin targets cannot survive the narrower CHECK, so they are dropped.

PRAGMA foreign_keys=OFF;

BEGIN;

CREATE TABLE managed_targets_old (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    host           TEXT NOT NULL,
    discovery_mode TEXT NOT NULL DEFAULT 'agent'
                   CHECK (discovery_mode IN ('agent', 'network', 'cloud', 'winrm', 'none')),
    install_mode   TEXT NOT NULL DEFAULT 'agent'
                   CHECK (install_mode IN ('agent', 'ssh', 'f5', 'citrix', 'k8s', 'iis', 'keychain', 'cloud', 'acme')),
    renewal_method TEXT NOT NULL DEFAULT 'acme'
                   CHECK (renewal_method IN ('acme', 'est', 'scep', 'manual')),
    credential_ref TEXT,
    schedule       TEXT,
    tenant         TEXT NOT NULL DEFAULT 'default',
    created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    renewal_threshold_days INTEGER
                   CHECK (renewal_threshold_days IS NULL OR renewal_threshold_days > 0),
    install_server_type   TEXT,
    install_cert_path     TEXT,
    install_key_path      TEXT,
    install_reload_method TEXT,
    auto_renew            INTEGER NOT NULL DEFAULT 0
);

INSERT INTO managed_targets_old
    (id, name, host, discovery_mode, install_mode, renewal_method,
     credential_ref, schedule, tenant, created_at, updated_at,
     renewal_threshold_days,
     install_server_type, install_cert_path, install_key_path,
     install_reload_method, auto_renew)
SELECT
     id, name, host, discovery_mode, install_mode, renewal_method,
     credential_ref, schedule, tenant, created_at, updated_at,
     renewal_threshold_days,
     install_server_type, install_cert_path, install_key_path,
     install_reload_method, auto_renew
FROM managed_targets WHERE install_mode <> 'plugin';

DROP TABLE managed_targets;

ALTER TABLE managed_targets_old RENAME TO managed_targets;

CREATE INDEX IF NOT EXISTS idx_managed_targets_tenant ON managed_targets(tenant);
CREATE INDEX IF NOT EXISTS idx_managed_targets_host ON managed_targets(host);

COMMIT;

PRAGMA foreign_keys=ON;
