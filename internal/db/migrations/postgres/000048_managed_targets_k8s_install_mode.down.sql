-- Wave W17 (PostgreSQL) -- rollback of 000048.
-- Restores the 000028 CHECK. Any existing 'k8s' rows would violate it, so
-- they are rejected rather than silently rewritten: a rollback must not
-- quietly change what a target IS.

BEGIN;

ALTER TABLE managed_targets
    DROP CONSTRAINT IF EXISTS managed_targets_install_mode_check;

ALTER TABLE managed_targets
    ADD CONSTRAINT managed_targets_install_mode_check
    CHECK (install_mode IN ('agent', 'ssh', 'f5', 'citrix', 'cloud', 'acme'));

COMMIT;
