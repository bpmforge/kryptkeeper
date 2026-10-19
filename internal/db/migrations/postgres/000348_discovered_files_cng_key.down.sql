-- Rollback pair of 000348. cng_key rows are derived from WinRM scans and are
-- rebuilt by the next one.
DELETE FROM discovered_files WHERE kind = 'cng_key';
ALTER TABLE discovered_files DROP CONSTRAINT IF EXISTS discovered_files_kind_check;
ALTER TABLE discovered_files ADD CONSTRAINT discovered_files_kind_check
    CHECK (kind IN ('pem', 'jks', 'p12', 'key', 'config'));
