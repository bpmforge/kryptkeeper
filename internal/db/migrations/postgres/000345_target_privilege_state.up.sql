-- Purpose: W34-10 (FR-P26, FR-P27, D-207). What the latest scan could and
-- could not do on a target, and why renewal is Blocked:
--   last_privilege_mode  privilege mode the latest scan ran with (none|nopasswd|password|helper)
--   unreadable_count     paths the scan account could not read
--   last_scanned_at      when that scan finished
--   blocked_kind/reason/at  a hard stop the scheduler honours: privilege (a
--                        root-owned install path with no privileged credential)
--                        or rollback (a failed rollback left the host in an
--                        unknown state)
-- renewal_privilege_required itself was added by 000342.
-- ADD COLUMN IF NOT EXISTS: the managed-target store self-heals the same columns.
-- Depends on: 000342
-- Rollback pair: 000345_target_privilege_state.down.sql

ALTER TABLE managed_targets ADD COLUMN IF NOT EXISTS last_privilege_mode TEXT;
ALTER TABLE managed_targets ADD COLUMN IF NOT EXISTS unreadable_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE managed_targets ADD COLUMN IF NOT EXISTS last_scanned_at TEXT;
ALTER TABLE managed_targets ADD COLUMN IF NOT EXISTS blocked_kind TEXT;
ALTER TABLE managed_targets ADD COLUMN IF NOT EXISTS blocked_reason TEXT;
ALTER TABLE managed_targets ADD COLUMN IF NOT EXISTS blocked_at TEXT;
