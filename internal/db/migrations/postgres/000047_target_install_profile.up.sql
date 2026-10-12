-- S-17 (PostgreSQL)
-- Purpose: per-target install profile + auto_renew opt-in for the hub-side
-- renewal sweep (W5-13 engine). Empty/0 = target is notify-only.
-- Depends on: 000028 (managed_targets)
-- Rollback pair: 000047_target_install_profile.down.sql

BEGIN;

ALTER TABLE managed_targets ADD COLUMN install_server_type TEXT;
ALTER TABLE managed_targets ADD COLUMN install_cert_path TEXT;
ALTER TABLE managed_targets ADD COLUMN install_key_path TEXT;
ALTER TABLE managed_targets ADD COLUMN install_reload_method TEXT;
-- INTEGER 0/1 on purpose, matching the sqlite shape and the store's writer:
-- a BOOLEAN here would recreate the exact writer-vs-schema split S-66 fixed.
ALTER TABLE managed_targets ADD COLUMN auto_renew INTEGER NOT NULL DEFAULT 0;

COMMIT;
