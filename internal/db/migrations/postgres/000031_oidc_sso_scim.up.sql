-- Wave W6 (PostgreSQL)
-- Purpose: SCIM 2.0 group provisioning + IdP group -> Kryptkeeper role mapping (W6-02, FR-P11)
-- Depends on: 000001_foundations_identity (users table)
-- Rollback pair: 000031_oidc_sso_scim.down.sql
--
-- OIDC SSO login itself needs no new schema: ID-token issuer/audience/JWKS
-- validation reuses the existing auth_jwks.go/auth_oidc.go path, PKCE
-- state/verifier is single-use short-lived (in-memory, matching the existing
-- refresh-session tradeoff in auth_bootstrap.go), and SCIM Users provisions
-- against the users table's existing oidc_subject/oidc_issuer columns
-- (migration 000001). SCIM Groups is the one durable new concept: an IdP
-- pushes group membership over SCIM, and that membership must survive a
-- restart for GET/PATCH/DELETE to behave consistently.

BEGIN;

CREATE TABLE IF NOT EXISTS scim_groups (
    id            TEXT PRIMARY KEY,
    display_name  TEXT NOT NULL UNIQUE,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scim_group_members (
    group_id      TEXT NOT NULL REFERENCES scim_groups(id) ON DELETE CASCADE,
    user_id       TEXT NOT NULL,
    added_at      TEXT NOT NULL,
    PRIMARY KEY (group_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_scim_group_members_user ON scim_group_members(user_id);

COMMIT;
