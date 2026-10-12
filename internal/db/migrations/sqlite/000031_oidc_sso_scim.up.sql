-- Wave W6 (SQLite)
-- Purpose: SCIM 2.0 group provisioning + IdP group -> Kryptkeeper role mapping (W6-02, FR-P11)
-- Depends on: 000001_foundations_identity (users table)
-- Rollback pair: 000031_oidc_sso_scim.down.sql
--
-- See the PostgreSQL sibling for why OIDC login itself needs no new schema
-- and why SCIM Groups is the one durable new concept here.

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
