-- W27-24: per-domain DCV validation lifetime tracking. Timestamps are
-- RFC3339 TEXT, like the other bootstrap stores.
CREATE TABLE IF NOT EXISTS dcv_validations (
    domain       TEXT NOT NULL,
    connector_id TEXT NOT NULL,
    tenant       TEXT NOT NULL DEFAULT 'default',
    validated_at TEXT NOT NULL,
    reuse_days   INTEGER NOT NULL,
    expires_at   TEXT NOT NULL,
    warned_at    TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (domain, connector_id)
);
CREATE INDEX IF NOT EXISTS idx_dcv_validations_tenant ON dcv_validations(tenant);
