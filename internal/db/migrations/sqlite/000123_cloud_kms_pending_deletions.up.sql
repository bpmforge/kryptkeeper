-- W23-22: tombstones for cloud-KMS keys whose provider-side deletion is
-- scheduled. CloudKMSStore.Delete drops the cloud_kms_keys reference after the
-- provider accepts the destroy; without this row nothing remembers the key URI
-- or public key, so a deletion could never be cancelled inside the provider's
-- recovery window. Public key only; no private material is ever stored.
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
