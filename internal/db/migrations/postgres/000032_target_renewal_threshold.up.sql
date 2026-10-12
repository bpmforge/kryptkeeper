-- Wave W8 (PostgreSQL)
-- Purpose: per-target auto-renew threshold, the other half of renewal_method
-- (000028) (W8-15, FR-P33)
-- Depends on: 000028 (managed_targets)
-- Rollback pair: 000032_target_renewal_threshold.down.sql

BEGIN;

ALTER TABLE managed_targets
    ADD COLUMN renewal_threshold_days INTEGER
    CHECK (renewal_threshold_days IS NULL OR renewal_threshold_days > 0);

COMMIT;
