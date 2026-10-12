-- Wave W9 (Postgres)
-- Purpose: Add cert_pem and key_id columns to certificate_authorities for CA engine persistence
-- Depends on: W2
-- Rollback pair: 000009_ca_engine_columns.down.sql

BEGIN;

ALTER TABLE certificate_authorities ADD COLUMN IF NOT EXISTS cert_pem TEXT;
ALTER TABLE certificate_authorities ADD COLUMN IF NOT EXISTS key_id TEXT;

COMMIT;
