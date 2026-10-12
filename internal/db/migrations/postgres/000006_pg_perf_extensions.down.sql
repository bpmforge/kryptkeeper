-- Wave W6 rollback (PostgreSQL)
-- Paired with: 000006_pg_perf_extensions.up.sql

BEGIN;

DROP INDEX IF EXISTS idx_cert_high_risk_partial;
DROP INDEX IF EXISTS idx_cert_subject_trgm;
DROP INDEX IF EXISTS idx_cert_cn_trgm;

-- Keep extension removal optional/safe for shared DBs.
DROP EXTENSION IF EXISTS pg_trgm;

COMMIT;
