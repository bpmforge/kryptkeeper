-- Wave W26 (W26-09): API-managed CMP credentials. kind 'pbm' holds a sealed
-- PasswordBasedMac shared secret named by sender_kid; kind 'trust_anchor'
-- holds a certificate (registered, not yet enforced). Times are RFC 3339 UTC
-- text. A revoked row is kept so its sender_kid is never reissued.
-- Rollback pair: 000183_cmp_credentials.down.sql

CREATE TABLE IF NOT EXISTS cmp_credentials (
    id                   TEXT PRIMARY KEY,
    kind                 TEXT NOT NULL CHECK (kind IN ('pbm', 'trust_anchor')),
    label                TEXT NOT NULL DEFAULT '',
    sender_kid           TEXT,
    sealed_secret        TEXT,
    cert_pem             TEXT,
    cert_sha256          TEXT,
    allowed_dns_suffixes TEXT NOT NULL DEFAULT '[]',
    created_by           TEXT NOT NULL,
    created_at           TEXT NOT NULL,
    rotated_at           TEXT,
    revoked_at           TEXT,
    last_used_at         TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_cmp_credentials_kid
    ON cmp_credentials(sender_kid) WHERE sender_kid IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_cmp_credentials_anchor
    ON cmp_credentials(cert_sha256) WHERE cert_sha256 IS NOT NULL AND revoked_at IS NULL;
