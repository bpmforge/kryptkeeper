BEGIN;

DELETE FROM managed_targets WHERE install_mode = 'plugin';
DROP INDEX IF EXISTS idx_managed_targets_plugin;
ALTER TABLE managed_targets DROP COLUMN IF EXISTS plugin_settings;
ALTER TABLE managed_targets DROP COLUMN IF EXISTS plugin_id;
ALTER TABLE managed_targets DROP CONSTRAINT IF EXISTS managed_targets_install_mode_check;
ALTER TABLE managed_targets ADD CONSTRAINT managed_targets_install_mode_check
    CHECK (install_mode IN ('agent', 'ssh', 'f5', 'citrix', 'k8s', 'iis', 'keychain', 'cloud', 'acme'));

COMMIT;
