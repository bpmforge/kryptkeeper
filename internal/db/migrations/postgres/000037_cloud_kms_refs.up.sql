-- W9-02 (PostgreSQL) — persisted cloud-KMS key references.
-- Depends on: none (standalone table)
-- Rollback pair: 000037_cloud_kms_refs.down.sql

BEGIN;

CREATE TABLE IF NOT EXISTS cloud_kms_keys (
    id             TEXT PRIMARY KEY,
    provider       TEXT NOT NULL CHECK (provider IN ('aws', 'gcp', 'azure')),
    key_uri        TEXT NOT NULL,
    region         TEXT,
    project_id     TEXT,
    algorithm      TEXT NOT NULL,
    public_key_pem TEXT NOT NULL,
    created_at     TEXT NOT NULL
);

COMMIT;
