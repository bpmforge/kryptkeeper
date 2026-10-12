-- Wave W18 (SQLite)
-- Purpose: admit install_mode 'iis' and discovery_mode 'winrm' (W18-03).
--
-- Same defect class as W17-11, twice over. Two finished implementations
-- could not be selected, stored or invoked because the vocabulary the
-- database accepts never learned about them:
--   * agentinstall/iis.go (was iis_windows.go) — a complete IIS installer:
--     certutil PFX import, netsh http binding, rollback that captures the
--     prior sslcert state.
--   * agentdiscovery/agentless_winrm.go — agentless WinRM discovery.
--
-- SQLite has no ALTER TABLE ... DROP CONSTRAINT, so this uses the rebuild
-- dance. The column list below is the table's CURRENT shape, which is
-- 000028 PLUS 000032 (renewal_threshold_days) PLUS 000047 (the five
-- install_*/auto_renew columns). 000048 changed only the CHECK, not the
-- columns. Copying 000028's original list would silently drop six columns
-- — the exact mistake W17-11 made and its rollback test caught.
-- Depends on: 000028, 000032, 000047, 000048
-- Rollback pair: 000050_windows_target_modes.down.sql

PRAGMA foreign_keys=OFF;

BEGIN;

CREATE TABLE managed_targets_new (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    host           TEXT NOT NULL,
    discovery_mode TEXT NOT NULL DEFAULT 'agent'
                   CHECK (discovery_mode IN ('agent', 'network', 'cloud', 'winrm', 'none')),
    install_mode   TEXT NOT NULL DEFAULT 'agent'
                   CHECK (install_mode IN ('agent', 'ssh', 'f5', 'citrix', 'k8s', 'iis', 'cloud', 'acme')),
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

INSERT INTO managed_targets_new
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
FROM managed_targets;

DROP TABLE managed_targets;

ALTER TABLE managed_targets_new RENAME TO managed_targets;

CREATE INDEX IF NOT EXISTS idx_managed_targets_tenant ON managed_targets(tenant);
CREATE INDEX IF NOT EXISTS idx_managed_targets_host ON managed_targets(host);

COMMIT;

PRAGMA foreign_keys=ON;
