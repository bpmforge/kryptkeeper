-- W29-11 (PostgreSQL) — CI OIDC trust rules and jti replay ledger.
-- Rollback pair: 000241_codesign_oidc_trust.down.sql

BEGIN;

CREATE TABLE IF NOT EXISTS codesign_oidc_trust_rules (
    id           TEXT PRIMARY KEY,
    provider     TEXT NOT NULL,
    issuer       TEXT NOT NULL,
    audience     TEXT NOT NULL,
    repo_pattern TEXT NOT NULL,
    ref_pattern  TEXT NOT NULL,
    ca_id        TEXT NOT NULL,
    tenant       TEXT NOT NULL DEFAULT 'default',
    created_by   TEXT NOT NULL,
    approved_by  TEXT NOT NULL,
    created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_codesign_trust_issuer ON codesign_oidc_trust_rules(issuer);

CREATE TABLE IF NOT EXISTS codesign_oidc_jti (
    issuer     TEXT NOT NULL,
    jti        TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    PRIMARY KEY (issuer, jti)
);
CREATE INDEX IF NOT EXISTS idx_codesign_jti_exp ON codesign_oidc_jti(expires_at);

COMMIT;
