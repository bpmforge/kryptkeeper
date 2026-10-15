-- (PostgreSQL)
-- Purpose: record WHOSE certificate a discovered leaf is. trust_class is the
-- verdict of a real x509 chain verification against the system roots and this
-- hub's own CAs (managed|public|private_other|self_signed|unknown); NULL means
-- never classified and reads back as "unknown". is_ca marks intermediate/root
-- certs captured from a served chain so they stay queryable but are kept out
-- of the leaf inventory and its counts.
-- Depends on: 000002
-- Rollback pair: 000077_certificates_trust_class.down.sql

ALTER TABLE certificates ADD COLUMN IF NOT EXISTS trust_class TEXT;
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS is_ca BOOLEAN NOT NULL DEFAULT FALSE;
