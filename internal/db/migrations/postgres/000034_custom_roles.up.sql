-- W6-08 (PostgreSQL) — custom RBAC roles + separation-of-duties pairs.
-- Depends on: 000002
-- Rollback pair: 000034_custom_roles.down.sql

BEGIN;

CREATE TABLE IF NOT EXISTS custom_roles (
    name        TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    permissions TEXT NOT NULL DEFAULT '[]',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS role_sod_constraints (
    id           TEXT PRIMARY KEY,
    permission_a TEXT NOT NULL,
    permission_b TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    UNIQUE (permission_a, permission_b)
);

COMMIT;
