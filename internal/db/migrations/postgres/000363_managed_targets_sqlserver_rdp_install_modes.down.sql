-- Rollback of 000363 (PostgreSQL): targets in the two new modes cannot survive
-- the narrower CHECK, so they are removed.

BEGIN;

DELETE FROM managed_targets WHERE install_mode IN ('sqlserver', 'rdp');
ALTER TABLE managed_targets DROP CONSTRAINT IF EXISTS managed_targets_install_mode_check;
ALTER TABLE managed_targets ADD CONSTRAINT managed_targets_install_mode_check
    CHECK (install_mode IN ('agent', 'ssh', 'f5', 'citrix', 'k8s', 'iis', 'keychain', 'cloud', 'acme', 'plugin'));

COMMIT;
