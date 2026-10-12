-- Wave W9 (SQLite)
-- Purpose: Add cert_pem and key_id columns to certificate_authorities for CA engine persistence
-- Depends on: W2
-- Rollback pair: 000009_ca_engine_columns.down.sql

BEGIN;

ALTER TABLE certificate_authorities ADD COLUMN cert_pem TEXT;
ALTER TABLE certificate_authorities ADD COLUMN key_id TEXT;

COMMIT;
