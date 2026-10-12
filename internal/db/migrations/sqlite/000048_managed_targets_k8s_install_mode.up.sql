-- Wave W17 (SQLite)
-- Purpose: allow install_mode 'k8s' on managed_targets (W17-11).
--
-- renewal_executor.go has routed and pushed install_mode 'k8s' since W5-04
-- (the Istio / ingress-gateway serving-cert path), but 000028's CHECK never
-- listed it. No k8s target could ever be persisted, so that push branch was
-- unreachable in practice -- a data-layer orphan of the same class the W17
-- wave cleared at the package level. Found while wiring W17-07.
--
-- SQLite has no ALTER TABLE ... DROP CONSTRAINT, so this uses the standard
-- rebuild dance (000042's pattern).
--
-- IMPORTANT: the column list below is the table's CURRENT shape, which is
-- 000028 PLUS 000032 (renewal_threshold_days) PLUS 000047 (the five
-- install_* / auto_renew columns). A rebuild that copies only the original
-- 000028 columns silently DROPS everything added since -- the first draft of
-- this migration did exactly that and the rollback test caught it
-- ("no such column: install_server_type" when 000047 rolled back).
--
-- legacy_alter_table is NOT needed here: no trigger references
-- managed_targets, unlike the certificates rebuild in 000042 that required it.
-- Depends on: 000028, 000032, 000047
-- Rollback pair: 000048_managed_targets_k8s_install_mode.down.sql

PRAGMA foreign_keys=OFF;

BEGIN;

CREATE TABLE managed_targets_new (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    host           TEXT NOT NULL,
    discovery_mode TEXT NOT NULL DEFAULT 'agent'
                   CHECK (discovery_mode IN ('agent', 'network', 'cloud', 'none')),
    install_mode   TEXT NOT NULL DEFAULT 'agent'
                   CHECK (install_mode IN ('agent', 'ssh', 'f5', 'citrix', 'k8s', 'cloud', 'acme')),
    renewal_method TEXT NOT NULL DEFAULT 'acme'
                   CHECK (renewal_method IN ('acme', 'est', 'scep', 'manual')),
    credential_ref TEXT,
    schedule       TEXT,
    tenant         TEXT NOT NULL DEFAULT 'default',
    created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    -- 000032
    renewal_threshold_days INTEGER
                   CHECK (renewal_threshold_days IS NULL OR renewal_threshold_days > 0),
    -- 000047
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
