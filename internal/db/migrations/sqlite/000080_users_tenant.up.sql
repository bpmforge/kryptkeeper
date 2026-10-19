-- (SQLite) Users belong to a tenant. '' means DefaultTenant, so every existing
-- account stays in the default tenant and nothing is re-homed by this migration.
ALTER TABLE users ADD COLUMN tenant TEXT NOT NULL DEFAULT '';
