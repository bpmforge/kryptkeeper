-- Wave W17 (SQLite)
-- Purpose: rollback of 000048 -- restore the 000028 install_mode CHECK.
--
-- The column list is the table's CURRENT shape (000028 + 000032 + 000047),
-- NOT 000028's original columns: a rollback that copies only the original
-- set would drop everything added since and break 000047's own rollback.
--
-- NOTE: any existing 'k8s' row violates the restored CHECK, so the copy
-- fails and the rollback aborts. That is deliberate: a rollback must not
-- silently rewrite what a target IS. Retarget or remove k8s targets first.
-- Pairs with: 000048_managed_targets_k8s_install_mode.up.sql

PRAGMA foreign_keys=OFF;

BEGIN;

CREATE TABLE managed_targets_new (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    host           TEXT NOT NULL,
    discovery_mode TEXT NOT NULL DEFAULT 'agent'
                   CHECK (discovery_mode IN ('agent', 'network', 'cloud', 'none')),
    install_mode   TEXT NOT NULL DEFAULT 'agent'
                   CHECK (install_mode IN ('agent', 'ssh', 'f5', 'citrix', 'cloud', 'acme')),
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
