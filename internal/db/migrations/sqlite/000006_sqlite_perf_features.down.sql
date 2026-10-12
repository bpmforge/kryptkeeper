-- Wave W6 rollback (SQLite)
-- Paired with: 000006_sqlite_perf_features.up.sql
--
-- W10-01/G-33: the FTS5 virtual table/triggers this rollback used to drop
-- were removed from the .up.sql (see its header comment) -- there is nothing
-- FTS5-related left to roll back.

BEGIN;

DROP INDEX IF EXISTS idx_cert_valid_window;
DROP INDEX IF EXISTS idx_cert_subject_dn;

COMMIT;
