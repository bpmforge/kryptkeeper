-- Rollback pair of 000345.
ALTER TABLE managed_targets DROP COLUMN IF EXISTS blocked_at;
ALTER TABLE managed_targets DROP COLUMN IF EXISTS blocked_reason;
ALTER TABLE managed_targets DROP COLUMN IF EXISTS blocked_kind;
ALTER TABLE managed_targets DROP COLUMN IF EXISTS last_scanned_at;
ALTER TABLE managed_targets DROP COLUMN IF EXISTS unreadable_count;
ALTER TABLE managed_targets DROP COLUMN IF EXISTS last_privilege_mode;
