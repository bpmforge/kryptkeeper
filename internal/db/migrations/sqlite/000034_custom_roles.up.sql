-- W6-08 (D-049/FR-P11): admin-defined RBAC roles composed from the
-- permission vocabulary, plus separation-of-duties constraint pairs no
-- single role may hold together.
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
