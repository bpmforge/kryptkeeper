-- Purpose: W34-06 (FR-P27, D-205). The operator's declared "CA groups":
-- authorized_issuers holds a CA certificate (PEM), an issuer DN or an SPKI
-- SHA-256 per tenant, and certificates.issuer_class records, per discovered
-- certificate, whose accountability the issuer falls under (hub, authorized,
-- public, private_unknown, self_signed, unknown). trust_class is untouched:
-- it stays the pure chain-verification verdict. Tenant '' is the default
-- tenant, as on endpoints (000083). Times are RFC3339 UTC text.
-- ADD COLUMN may already exist when the discovery provider's EnsureSchema ran
-- first; this migration is in migrationsTolerateAlreadySatisfied.
-- Rollback pair: 000341_authorized_issuers.down.sql

CREATE TABLE IF NOT EXISTS authorized_issuers (
    id          TEXT PRIMARY KEY,
    tenant      TEXT NOT NULL DEFAULT '',
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL CHECK (kind IN ('ca_cert', 'issuer_dn', 'spki_sha256')),
    value       TEXT NOT NULL,
    notes       TEXT NOT NULL DEFAULT '',
    created_by  TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_authorized_issuers_identity ON authorized_issuers(tenant, kind, value);

ALTER TABLE certificates ADD COLUMN issuer_class TEXT CHECK (issuer_class IS NULL OR issuer_class IN ('hub', 'authorized', 'public', 'private_unknown', 'self_signed', 'unknown'));
