-- Wave W1 (PostgreSQL)
-- Purpose: foundations + identity tables
-- Depends on: none
-- Rollback pair: 000001_foundations_identity.down.sql

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS trigger AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TABLE users (
    id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email                     VARCHAR(255) NOT NULL UNIQUE,
    display_name              VARCHAR(255),
    role                      VARCHAR(30) NOT NULL DEFAULT 'pki-viewer'
                              CHECK (role IN (
                                  'pki-admin',
                                  'pki-operator',
                                  'pki-viewer',
                                  'pki-auditor',
                                  'discovery-operator',
                                  'service-account'
                              )),
    oidc_subject              VARCHAR(255),
    oidc_issuer               VARCHAR(255),
    password_hash             VARCHAR(255),
    active                    BOOLEAN NOT NULL DEFAULT TRUE,
    last_login_at             TIMESTAMPTZ,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT user_oidc_unique UNIQUE (oidc_subject, oidc_issuer)
);

CREATE TABLE notification_policies (
    id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                      VARCHAR(255) NOT NULL,
    expiry_thresholds         JSONB NOT NULL DEFAULT '[90, 30, 7]',
    alert_on_risk_flags       TEXT[] NOT NULL DEFAULT '{"EXPIRED","EXPIRING_7_DAYS","WEAK_KEY"}',
    alert_cooldown_hours      INTEGER NOT NULL DEFAULT 24,
    active                    BOOLEAN NOT NULL DEFAULT TRUE,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE teams (
    id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                      VARCHAR(255) NOT NULL UNIQUE,
    slug                      VARCHAR(100) NOT NULL UNIQUE,
    description               TEXT,
    notification_policy_id    UUID REFERENCES notification_policies(id),
    created_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE team_members (
    team_id                   UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id                   UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role                      VARCHAR(20) NOT NULL DEFAULT 'member'
                              CHECK (role IN ('owner', 'member')),
    added_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (team_id, user_id)
);

CREATE TABLE api_keys (
    id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                   UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name                      VARCHAR(255) NOT NULL,
    kid                       VARCHAR(32) NOT NULL UNIQUE,
    key_hash                  CHAR(64) NOT NULL UNIQUE,
    key_prefix                VARCHAR(16) NOT NULL,
    scopes                    TEXT[] NOT NULL DEFAULT '{"read:certificates"}',
    expires_at                TIMESTAMPTZ,
    last_used_at              TIMESTAMPTZ,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
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
BEFORE UPDATE ON users
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_notification_policies_set_updated_at
BEFORE UPDATE ON notification_policies
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_teams_set_updated_at
BEFORE UPDATE ON teams
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

COMMIT;
