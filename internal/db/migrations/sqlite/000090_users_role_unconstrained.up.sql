-- (SQLite) W22-19: users.role was pinned to six legacy names by 000001, but the
-- runtime role vocabulary is viewer / auditor / approver / custom roles, and an
-- SSO user with no mapped group is stored with an empty role (denied at login).
-- The CHECK made every such write fail (SCIM create, SSO role persist). Role
-- validity is enforced in the application (roleKnown / custom roles).
--
-- SQLite cannot drop a CHECK, so this is the rebuild dance with users' CURRENT
-- columns (000001 + 000080 tenant), keeping the indexes and updated_at trigger.
-- Rollback pair: 000090_users_role_unconstrained.down.sql

PRAGMA foreign_keys=OFF;

BEGIN;

CREATE TABLE users_new (
    id                        TEXT PRIMARY KEY,
    email                     TEXT NOT NULL UNIQUE,
    display_name              TEXT,
    role                      TEXT NOT NULL DEFAULT 'pki-viewer',
    oidc_subject              TEXT,
    oidc_issuer               TEXT,
    password_hash             TEXT,
    active                    INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
    last_login_at             TEXT,
    created_at                TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at                TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    tenant                    TEXT NOT NULL DEFAULT '',
    UNIQUE (oidc_subject, oidc_issuer)
);

INSERT INTO users_new
    (id, email, display_name, role, oidc_subject, oidc_issuer, password_hash,
     active, last_login_at, created_at, updated_at, tenant)
SELECT
     id, email, display_name, role, oidc_subject, oidc_issuer, password_hash,
     active, last_login_at, created_at, updated_at, tenant
FROM users;

DROP TABLE users;

ALTER TABLE users_new RENAME TO users;

CREATE INDEX IF NOT EXISTS idx_user_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_user_active ON users(active);

CREATE TRIGGER IF NOT EXISTS trg_users_set_updated_at
AFTER UPDATE ON users
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE users
       SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
     WHERE id = NEW.id;
END;

COMMIT;

PRAGMA foreign_keys=ON;
