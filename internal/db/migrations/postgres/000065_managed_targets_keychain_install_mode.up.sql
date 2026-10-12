-- Wave W18 (PostgreSQL)
-- Purpose: admit install_mode 'keychain' (W18-05): agentless install into a
-- remote macOS System keychain over SSH (agentinstall/keychain.go).
-- Depends on: 000028, 000050
-- Rollback pair: 000065_managed_targets_keychain_install_mode.down.sql

BEGIN;

ALTER TABLE managed_targets DROP CONSTRAINT IF EXISTS managed_targets_install_mode_check;
ALTER TABLE managed_targets ADD CONSTRAINT managed_targets_install_mode_check
    CHECK (install_mode IN ('agent', 'ssh', 'f5', 'citrix', 'k8s', 'iis', 'keychain', 'cloud', 'acme'));

COMMIT;
