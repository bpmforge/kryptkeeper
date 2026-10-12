-- Wave W1 rollback (PostgreSQL)
-- Purpose: rollback foundations + identity tables
-- Paired with: 000001_foundations_identity.up.sql

BEGIN;

DROP TRIGGER IF EXISTS trg_teams_set_updated_at ON teams;
DROP TRIGGER IF EXISTS trg_notification_policies_set_updated_at ON notification_policies;
DROP TRIGGER IF EXISTS trg_users_set_updated_at ON users;

DROP INDEX IF EXISTS idx_teams_notification_policy;
DROP INDEX IF EXISTS idx_api_key_kid;
DROP INDEX IF EXISTS idx_api_key_user;
DROP INDEX IF EXISTS idx_api_key_hash;
DROP INDEX IF EXISTS idx_team_members_user;
DROP INDEX IF EXISTS idx_user_active;
DROP INDEX IF EXISTS idx_user_email;

DROP TABLE IF EXISTS api_keys;
DROP TABLE IF EXISTS team_members;
DROP TABLE IF EXISTS teams;
DROP TABLE IF EXISTS notification_policies;
DROP TABLE IF EXISTS users;

DROP FUNCTION IF EXISTS set_updated_at();

COMMIT;
