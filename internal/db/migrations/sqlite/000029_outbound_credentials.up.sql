CREATE TABLE IF NOT EXISTS outbound_credentials (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    credential_type TEXT NOT NULL
                    CHECK (credential_type IN ('ssh_key', 'api_token', 'cloud_iam')),
    tenant          TEXT NOT NULL DEFAULT 'default',
    envelope        TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE INDEX IF NOT EXISTS idx_outbound_credentials_tenant ON outbound_credentials(tenant);
