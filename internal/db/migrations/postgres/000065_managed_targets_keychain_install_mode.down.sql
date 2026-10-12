-- Wave W18 (PostgreSQL)
-- Purpose: rollback of 000065 -- restore the 000050 vocabulary. Existing
-- keychain rows violate it, which is deliberate.
-- Depends on: 000050
-- Pairs with: 000065_managed_targets_keychain_install_mode.up.sql

BEGIN;

ALTER TABLE managed_targets DROP CONSTRAINT IF EXISTS managed_targets_install_mode_check;
ALTER TABLE managed_targets ADD CONSTRAINT managed_targets_install_mode_check
    CHECK (install_mode IN ('agent', 'ssh', 'f5', 'citrix', 'k8s', 'iis', 'cloud', 'acme'));

COMMIT;
