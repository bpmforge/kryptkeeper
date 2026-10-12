-- Optional post-install verification address for scheduled renewals (host:port); empty = <host>:443.
-- Depends on: 000028 (managed_targets)
-- Rollback pair: 000071_managed_targets_verify_host_port.down.sql

BEGIN;

ALTER TABLE managed_targets ADD COLUMN verify_host_port TEXT;

COMMIT;
