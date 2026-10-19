-- Rollback pair of 000345.
ALTER TABLE managed_targets DROP COLUMN blocked_at;
ALTER TABLE managed_targets DROP COLUMN blocked_reason;
ALTER TABLE managed_targets DROP COLUMN blocked_kind;
ALTER TABLE managed_targets DROP COLUMN last_scanned_at;
ALTER TABLE managed_targets DROP COLUMN unreadable_count;
ALTER TABLE managed_targets DROP COLUMN last_privilege_mode;
