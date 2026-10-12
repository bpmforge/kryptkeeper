-- W9-02 (G-34/D-080): persisted cloud-KMS key references. The private key
-- lives in the provider's KMS; this table holds the id -> key-URI mapping
-- and the public key, so a restart no longer orphans cloud keys.
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
