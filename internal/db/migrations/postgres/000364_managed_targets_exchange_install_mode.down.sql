-- Rollback of 000364 (PostgreSQL): back to the 000363 install modes. Exchange
-- targets cannot survive the narrower CHECK, so they are removed.

BEGIN;

DELETE FROM managed_targets WHERE install_mode = 'exchange';
ALTER TABLE managed_targets DROP CONSTRAINT IF EXISTS managed_targets_install_mode_check;
ALTER TABLE managed_targets ADD CONSTRAINT managed_targets_install_mode_check
    CHECK (install_mode IN ('agent', 'ssh', 'f5', 'citrix', 'k8s', 'iis', 'keychain', 'cloud', 'acme', 'plugin', 'sqlserver', 'rdp'));

COMMIT;
