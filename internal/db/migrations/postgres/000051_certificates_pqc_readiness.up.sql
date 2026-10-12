-- Wave W18 (PostgreSQL)
-- Purpose: persist certificates.pqc_readiness (found in end-user review).
-- computePQCReadiness ran at issuance but was never stored, so DB-backed
-- reads returned "" and the crypto-posture report showed 0 vulnerable and
-- a 0% PQC score for certificates flagged pqc_vulnerable = true.
-- Depends on: 000002
-- Rollback pair: 000051_certificates_pqc_readiness.down.sql

ALTER TABLE certificates ADD COLUMN IF NOT EXISTS pqc_readiness TEXT;
