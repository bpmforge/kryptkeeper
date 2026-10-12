-- Wave W20 (PostgreSQL) (W20-20): admit install_mode 'plugin' and add
-- plugin_id and plugin_settings (target_schema values, JSON).
-- Depends on: 000065
-- Rollback pair: 000068_managed_targets_plugin_install_mode.down.sql

BEGIN;

ALTER TABLE managed_targets DROP CONSTRAINT IF EXISTS managed_targets_install_mode_check;
ALTER TABLE managed_targets ADD CONSTRAINT managed_targets_install_mode_check
    CHECK (install_mode IN ('agent', 'ssh', 'f5', 'citrix', 'k8s', 'iis', 'keychain', 'cloud', 'acme', 'plugin'));
ALTER TABLE managed_targets ADD COLUMN IF NOT EXISTS plugin_id TEXT;
ALTER TABLE managed_targets ADD COLUMN IF NOT EXISTS plugin_settings TEXT NOT NULL DEFAULT '{}';
CREATE INDEX IF NOT EXISTS idx_managed_targets_plugin ON managed_targets(plugin_id);

COMMIT;
