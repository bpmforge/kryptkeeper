-- W5-05 (PostgreSQL) — data-driven issuance policies.
-- Depends on: 000002
-- Rollback pair: 000036_issuance_policy.down.sql

BEGIN;

CREATE TABLE IF NOT EXISTS issuance_policies (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    enabled    INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
    ca_id      TEXT NOT NULL DEFAULT '',
    rules      TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_issuance_policies_ca ON issuance_policies(ca_id, enabled);

COMMIT;
