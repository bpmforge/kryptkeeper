-- W35-02 / W35-04 (PostgreSQL): admit install_mode 'sqlserver' and 'rdp'.
-- Rollback pair: 000363_managed_targets_sqlserver_rdp_install_modes.down.sql

BEGIN;

ALTER TABLE managed_targets DROP CONSTRAINT IF EXISTS managed_targets_install_mode_check;
ALTER TABLE managed_targets ADD CONSTRAINT managed_targets_install_mode_check
    CHECK (install_mode IN ('agent', 'ssh', 'f5', 'citrix', 'k8s', 'iis', 'keychain', 'cloud', 'acme', 'plugin', 'sqlserver', 'rdp'));

COMMIT;
