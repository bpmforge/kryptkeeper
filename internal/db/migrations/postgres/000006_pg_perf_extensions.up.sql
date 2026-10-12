-- Wave W6 (PostgreSQL)
-- Purpose: engine-specific performance features
-- Depends on: W5
-- Rollback pair: 000006_pg_perf_extensions.down.sql

BEGIN;

CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- Inventory search acceleration
CREATE INDEX IF NOT EXISTS idx_cert_cn_trgm
    ON certificates USING GIN (common_name gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_cert_subject_trgm
    ON certificates USING GIN (subject_dn gin_trgm_ops);

-- Optional high-risk partial index for dashboard/top-N views
CREATE INDEX IF NOT EXISTS idx_cert_high_risk_partial
    ON certificates (risk_score DESC)
    WHERE risk_score > 40;

COMMIT;
