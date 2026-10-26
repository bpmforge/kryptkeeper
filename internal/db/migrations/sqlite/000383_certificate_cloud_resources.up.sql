-- W38-05 (D-323): where each cloud-found certificate row was seen (provider,
-- scope, resource id, account, region), kept apart from `certificates` because
-- one certificate can live in several resources and a resource can disappear.
-- The primary key includes tenant so one tenant's scan never refreshes or
-- retires another tenant's links.
-- Rollback pair: 000383_certificate_cloud_resources.down.sql
CREATE TABLE IF NOT EXISTS certificate_cloud_resources (
    provider           TEXT NOT NULL,
    scope_key          TEXT NOT NULL,
    resource_id        TEXT NOT NULL,
    tenant             TEXT NOT NULL DEFAULT '',
    fingerprint_sha256 TEXT NOT NULL,
    fingerprint_kind   TEXT NOT NULL CHECK (fingerprint_kind IN ('der', 'synthetic')),
    account            TEXT NOT NULL DEFAULT '',
    region             TEXT NOT NULL DEFAULT '',
    status             TEXT NOT NULL DEFAULT '',
    in_use             INTEGER NOT NULL DEFAULT 0,
    first_seen_at      TEXT NOT NULL,
    last_seen_at       TEXT NOT NULL,
    currently_active   INTEGER NOT NULL DEFAULT 1,
    removed_at         TEXT,
    PRIMARY KEY (provider, scope_key, resource_id, tenant)
);
CREATE INDEX IF NOT EXISTS idx_cloud_resources_fingerprint ON certificate_cloud_resources(fingerprint_sha256);
