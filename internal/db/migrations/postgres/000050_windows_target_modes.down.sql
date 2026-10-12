-- Wave W18 (PostgreSQL)
-- Purpose: rollback of 000050 -- restore the 000048 vocabulary. Existing
-- iis/winrm rows violate it, which is deliberate.
-- Two finished implementations (agentinstall/iis.go, agentdiscovery/
-- agentless_winrm.go) could not be stored or invoked because the accepted
-- vocabulary never learned about them -- the W17-11 class, twice.
-- Depends on: 000028, 000048
-- Rollback pair: 000050_windows_target_modes.down.sql

BEGIN;

ALTER TABLE managed_targets DROP CONSTRAINT IF EXISTS managed_targets_install_mode_check;
ALTER TABLE managed_targets ADD CONSTRAINT managed_targets_install_mode_check
    CHECK (install_mode IN ('agent', 'ssh', 'f5', 'citrix', 'k8s', 'cloud', 'acme'));

ALTER TABLE managed_targets DROP CONSTRAINT IF EXISTS managed_targets_discovery_mode_check;
ALTER TABLE managed_targets ADD CONSTRAINT managed_targets_discovery_mode_check
    CHECK (discovery_mode IN ('agent', 'network', 'cloud', 'none'));

COMMIT;
