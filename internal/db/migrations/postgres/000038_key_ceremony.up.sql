-- W9-06 (PostgreSQL) — M-of-N root-CA key ceremonies.
-- Depends on: 000002
-- Rollback pair: 000038_key_ceremony.down.sql

BEGIN;

CREATE TABLE IF NOT EXISTS key_ceremonies (
    id            TEXT PRIMARY KEY,
    ca_id         TEXT NOT NULL,
    ca_name       TEXT NOT NULL,
    common_name   TEXT NOT NULL,
    algorithm     TEXT NOT NULL,
    validity_days INTEGER NOT NULL CHECK (validity_days > 0),
    initiator     TEXT NOT NULL,
    approvers     TEXT NOT NULL,
    quorum        INTEGER NOT NULL CHECK (quorum >= 2),
    approvals     TEXT NOT NULL DEFAULT '[]',
    status        TEXT NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending', 'completed', 'aborted')),
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

COMMIT;
