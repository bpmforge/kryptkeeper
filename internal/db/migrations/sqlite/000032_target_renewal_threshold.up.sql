ALTER TABLE managed_targets ADD COLUMN renewal_threshold_days INTEGER
    CHECK (renewal_threshold_days IS NULL OR renewal_threshold_days > 0);
