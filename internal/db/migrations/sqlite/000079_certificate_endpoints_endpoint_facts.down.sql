-- (SQLite) rollback of 000079. Endpoint-scoped verdicts are discovery-owned and
-- re-derived by the next scan.
ALTER TABLE certificate_endpoints DROP COLUMN chain_trusted;
ALTER TABLE certificate_endpoints DROP COLUMN chain_complete;
ALTER TABLE certificate_endpoints DROP COLUMN endpoint_risk_score;
ALTER TABLE certificate_endpoints DROP COLUMN endpoint_flags;
