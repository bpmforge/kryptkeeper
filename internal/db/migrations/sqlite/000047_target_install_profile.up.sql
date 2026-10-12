-- S-17: per-target install profile + auto_renew opt-in for the hub-side
-- renewal sweep (W5-13 engine). Empty/0 = target is notify-only.
ALTER TABLE managed_targets ADD COLUMN install_server_type TEXT;
ALTER TABLE managed_targets ADD COLUMN install_cert_path TEXT;
ALTER TABLE managed_targets ADD COLUMN install_key_path TEXT;
ALTER TABLE managed_targets ADD COLUMN install_reload_method TEXT;
ALTER TABLE managed_targets ADD COLUMN auto_renew INTEGER NOT NULL DEFAULT 0;
