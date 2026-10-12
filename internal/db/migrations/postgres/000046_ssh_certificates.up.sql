-- W11-07 (PostgreSQL) — issued SSH certificates.
-- Depends on: 000002
-- Rollback pair: 000046_ssh_certificates.down.sql

BEGIN;

CREATE TABLE IF NOT EXISTS ssh_certificates (
    serial               TEXT PRIMARY KEY,
    cert_type            TEXT NOT NULL CHECK (cert_type IN ('user', 'host')),
    key_id               TEXT NOT NULL,
    principals           TEXT NOT NULL DEFAULT '[]',
    valid_after          TEXT NOT NULL,
    valid_before         TEXT NOT NULL,
    subject_fingerprint  TEXT NOT NULL,
    authority_fingerprint TEXT NOT NULL,
    certificate_line     TEXT NOT NULL,
    tenant               TEXT NOT NULL DEFAULT 'default',
    created_at           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ssh_certs_subject ON ssh_certificates(subject_fingerprint);
CREATE INDEX IF NOT EXISTS idx_ssh_certs_tenant ON ssh_certificates(tenant);

COMMIT;
