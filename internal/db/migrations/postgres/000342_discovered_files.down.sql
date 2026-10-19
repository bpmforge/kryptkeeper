-- Rollback pair of 000342. Posture rows are derived from scans and are
-- rebuilt by the next one, so dropping them loses no operator data.
ALTER TABLE managed_targets DROP COLUMN IF EXISTS renewal_privilege_required;
DROP TABLE IF EXISTS certificate_files;
DROP TABLE IF EXISTS discovered_files;
