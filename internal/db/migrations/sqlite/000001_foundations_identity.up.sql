-- Wave W1 (SQLite)
-- Purpose: foundations + identity tables
-- Depends on: none
-- Rollback pair: 000001_foundations_identity.down.sql

BEGIN;

CREATE TABLE users (
    id                        TEXT PRIMARY KEY,
    email                     TEXT NOT NULL UNIQUE,
    display_name              TEXT,
    role                      TEXT NOT NULL DEFAULT 'pki-viewer'
                              CHECK (role IN (
                                  'pki-admin',
                                  'pki-operator',
                                  'pki-viewer',
                                  'pki-auditor',
                                  'discovery-operator',
                                  'service-account'
                              )),
    oidc_subject              TEXT,
    oidc_issuer               TEXT,
    password_hash             TEXT,
    active                    INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
    last_login_at             TEXT,
    created_at                TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at                TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    UNIQUE (oidc_subject, oidc_issuer)
);

CREATE TABLE notification_policies (
    id                        TEXT PRIMARY KEY,
    name                      TEXT NOT NULL,
    expiry_thresholds         TEXT NOT NULL DEFAULT '[90,30,7]',
    alert_on_risk_flags       TEXT NOT NULL DEFAULT '["EXPIRED","EXPIRING_7_DAYS","WEAK_KEY"]',
    alert_cooldown_hours      INTEGER NOT NULL DEFAULT 24,
    active                    INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
    created_at                TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at                TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE teams (
    id                        TEXT PRIMARY KEY,
    name                      TEXT NOT NULL UNIQUE,
    slug                      TEXT NOT NULL UNIQUE,
    description               TEXT,
    notification_policy_id    TEXT REFERENCES notification_policies(id),
    created_at                TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at                TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE team_members (
    team_id                   TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id                   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role                      TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('owner','member')),
    added_at                  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (team_id, user_id)
);

CREATE TABLE api_keys (
    id                        TEXT PRIMARY KEY,
    user_id                   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name                      TEXT NOT NULL,
    kid                       TEXT NOT NULL UNIQUE,
    key_hash                  TEXT NOT NULL UNIQUE,
    key_prefix                TEXT NOT NULL,
    scopes                    TEXT NOT NULL DEFAULT '["read:certificates"]',
    expires_at                TEXT,
    last_used_at              TEXT,
    created_at                TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    CHECK (key_prefix LIKE 'kk_%')
);

CREATE INDEX idx_user_email ON users(email);
CREATE INDEX idx_user_active ON users(active);
CREATE INDEX idx_team_members_user ON team_members(user_id);
CREATE INDEX idx_api_key_hash ON api_keys(key_hash);
CREATE INDEX idx_api_key_user ON api_keys(user_id);
CREATE INDEX idx_api_key_kid ON api_keys(kid);
CREATE INDEX idx_teams_notification_policy ON teams(notification_policy_id);

CREATE TRIGGER trg_users_set_updated_at
AFTER UPDATE ON users
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE users
       SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
     WHERE id = NEW.id;
END;

CREATE TRIGGER trg_notification_policies_set_updated_at
AFTER UPDATE ON notification_policies
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE notification_policies
       SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
     WHERE id = NEW.id;
END;

CREATE TRIGGER trg_teams_set_updated_at
AFTER UPDATE ON teams
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE teams
       SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
     WHERE id = NEW.id;
END;

COMMIT;
