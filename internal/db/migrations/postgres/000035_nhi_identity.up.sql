-- W7-02 (PostgreSQL) — non-human identities with approval-governed issuance.
-- Depends on: 000002
-- Rollback pair: 000035_nhi_identity.down.sql

BEGIN;

CREATE TABLE IF NOT EXISTS nhi_identities (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL,
    spiffe_id   TEXT NOT NULL,
    scopes      TEXT NOT NULL DEFAULT '[]',
    status      TEXT NOT NULL DEFAULT 'pending',
    created_by  TEXT NOT NULL,
    decided_by  TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    decided_at  TEXT NOT NULL DEFAULT '',
    UNIQUE (name, kind)
);

COMMIT;
