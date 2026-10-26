-- W35-03 (PostgreSQL): admit install_mode 'exchange' (cumulative with 000363).
-- Rollback pair: 000364_managed_targets_exchange_install_mode.down.sql

BEGIN;

ALTER TABLE managed_targets DROP CONSTRAINT IF EXISTS managed_targets_install_mode_check;
ALTER TABLE managed_targets ADD CONSTRAINT managed_targets_install_mode_check
    CHECK (install_mode IN ('agent', 'ssh', 'f5', 'citrix', 'k8s', 'iis', 'keychain', 'cloud', 'acme', 'plugin', 'sqlserver', 'rdp', 'exchange'));

COMMIT;
