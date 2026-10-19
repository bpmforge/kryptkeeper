-- (SQLite) Restore the legacy role CHECK. Roles outside the legacy set are
-- coerced to the read-only 'pki-viewer' (lossy by design, never widens access).

PRAGMA foreign_keys=OFF;

BEGIN;

CREATE TABLE users_old (
    id                        TEXT PRIMARY KEY,
    email                     TEXT NOT NULL UNIQUE,
    display_name              TEXT,
    role                      TEXT NOT NULL DEFAULT 'pki-viewer'
                              CHECK (role IN (
                                  'pki-admin','pki-operator','pki-viewer',
                                  'pki-auditor','discovery-operator','service-account'
                              )),
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

INSERT INTO users_old
    (id, email, display_name, role, oidc_subject, oidc_issuer, password_hash,
     active, last_login_at, created_at, updated_at, tenant)
SELECT
     id, email, display_name,
     CASE WHEN role IN ('pki-admin','pki-operator','pki-viewer','pki-auditor','discovery-operator','service-account')
          THEN role ELSE 'pki-viewer' END,
     oidc_subject, oidc_issuer, password_hash,
     active, last_login_at, created_at, updated_at, tenant
FROM users;

DROP TABLE users;

ALTER TABLE users_old RENAME TO users;

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
