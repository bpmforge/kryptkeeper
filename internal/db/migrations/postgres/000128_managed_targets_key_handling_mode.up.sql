-- W23-46: where the target's private key is created and held
-- (client_csr | hub_generated | hsm_resident_ca | macos_non_extractable).
-- Nullable on purpose: existing rows stay unset and derive their effective
-- mode from install_mode. Not backfilled.
-- Depends on: 000028 (managed_targets)
-- Rollback pair: 000128_managed_targets_key_handling_mode.down.sql

BEGIN;

ALTER TABLE managed_targets ADD COLUMN key_handling_mode TEXT;

COMMIT;
