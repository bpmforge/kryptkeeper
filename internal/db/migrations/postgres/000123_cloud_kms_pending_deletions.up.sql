-- W23-22 (PostgreSQL): tombstones for cloud-KMS keys whose provider-side
-- deletion is scheduled, so the deletion can be cancelled inside the
-- provider's recovery window. Public key only; no private material.
-- Depends on: 000037_cloud_kms_refs
-- Rollback pair: 000123_cloud_kms_pending_deletions.down.sql

BEGIN;

CREATE TABLE IF NOT EXISTS cloud_kms_pending_deletions (
    id             TEXT PRIMARY KEY,
    provider       TEXT NOT NULL CHECK (provider IN ('aws', 'gcp', 'azure')),
    key_uri        TEXT NOT NULL,
    region         TEXT,
    project_id     TEXT,
    scheduled_at   TEXT NOT NULL,
    window_hours   INTEGER NOT NULL,
    algorithm      TEXT NOT NULL,
    public_key_pem TEXT NOT NULL,
    created_at     TEXT NOT NULL
);

COMMIT;
