-- W35-02 / W35-04 (SQLite): admit install_mode 'sqlserver' and 'rdp'.
--
-- SQLite cannot alter a CHECK, so the table is rebuilt with its CURRENT column
-- list (000068 plus every ADD COLUMN since). No table references
-- managed_targets by foreign key, so the rebuild orphans nothing.
-- Rollback pair: 000363_managed_targets_sqlserver_rdp_install_modes.down.sql

PRAGMA foreign_keys=OFF;

BEGIN;

CREATE TABLE managed_targets_new (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    host           TEXT NOT NULL,
    discovery_mode TEXT NOT NULL DEFAULT 'agent'
                   CHECK (discovery_mode IN ('agent', 'network', 'cloud', 'winrm', 'none')),
    install_mode   TEXT NOT NULL DEFAULT 'agent'
                   CHECK (install_mode IN ('agent', 'ssh', 'f5', 'citrix', 'k8s', 'iis', 'keychain', 'cloud', 'acme', 'plugin', 'sqlserver', 'rdp')),
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
    auto_renew            INTEGER NOT NULL DEFAULT 0,
    plugin_id             TEXT,
    plugin_settings       TEXT NOT NULL DEFAULT '{}',
    verify_host_port TEXT,
    auto_renew_set_by TEXT,
    key_handling_mode TEXT,
    ssh_host_key TEXT,
    renewal_privilege_required INTEGER NOT NULL DEFAULT 0,
    last_preflight TEXT,
    last_privilege_mode TEXT,
    unreadable_count INTEGER NOT NULL DEFAULT 0,
    last_scanned_at TEXT,
    blocked_kind TEXT,
    blocked_reason TEXT,
    blocked_at TEXT
);

INSERT INTO managed_targets_new
    (id, name, host, discovery_mode, install_mode, renewal_method, credential_ref, schedule, tenant, created_at, updated_at, renewal_threshold_days, install_server_type, install_cert_path, install_key_path, install_reload_method, auto_renew, plugin_id, plugin_settings, verify_host_port, auto_renew_set_by, key_handling_mode, ssh_host_key, renewal_privilege_required, last_preflight, last_privilege_mode, unreadable_count, last_scanned_at, blocked_kind, blocked_reason, blocked_at)
SELECT
     id, name, host, discovery_mode, install_mode, renewal_method, credential_ref, schedule, tenant, created_at, updated_at, renewal_threshold_days, install_server_type, install_cert_path, install_key_path, install_reload_method, auto_renew, plugin_id, plugin_settings, verify_host_port, auto_renew_set_by, key_handling_mode, ssh_host_key, renewal_privilege_required, last_preflight, last_privilege_mode, unreadable_count, last_scanned_at, blocked_kind, blocked_reason, blocked_at
FROM managed_targets;

DROP TABLE managed_targets;

ALTER TABLE managed_targets_new RENAME TO managed_targets;

CREATE INDEX IF NOT EXISTS idx_managed_targets_tenant ON managed_targets(tenant);
CREATE INDEX IF NOT EXISTS idx_managed_targets_host ON managed_targets(host);
CREATE INDEX IF NOT EXISTS idx_managed_targets_plugin ON managed_targets(plugin_id);

COMMIT;

PRAGMA foreign_keys=ON;
