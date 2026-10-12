-- W9-09 (PostgreSQL) — per-key lifecycle policy: owner/ACL, max-age
-- rotation schedule, compromise stamp.
-- Depends on: 000002
-- Rollback pair: 000039_key_acl_schedule.down.sql

BEGIN;

CREATE TABLE IF NOT EXISTS key_lifecycle (
    key_id         TEXT PRIMARY KEY,
    owner          TEXT NOT NULL,
    acl            TEXT NOT NULL DEFAULT '[]',
    max_age_days   INTEGER NOT NULL DEFAULT 0
                   CHECK (max_age_days >= 0),
    rotated_at     TEXT NOT NULL,
    compromised_at TEXT,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);

COMMIT;
