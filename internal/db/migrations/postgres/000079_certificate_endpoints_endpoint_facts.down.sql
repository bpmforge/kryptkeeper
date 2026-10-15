-- (PostgreSQL) rollback of 000079. Endpoint-scoped verdicts are discovery-owned
-- and re-derived by the next scan.
ALTER TABLE certificate_endpoints DROP COLUMN IF EXISTS chain_trusted;
ALTER TABLE certificate_endpoints DROP COLUMN IF EXISTS chain_complete;
ALTER TABLE certificate_endpoints DROP COLUMN IF EXISTS endpoint_risk_score;
ALTER TABLE certificate_endpoints DROP COLUMN IF EXISTS endpoint_flags;
