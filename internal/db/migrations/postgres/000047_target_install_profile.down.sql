BEGIN;

ALTER TABLE managed_targets DROP COLUMN install_server_type;
ALTER TABLE managed_targets DROP COLUMN install_cert_path;
ALTER TABLE managed_targets DROP COLUMN install_key_path;
ALTER TABLE managed_targets DROP COLUMN install_reload_method;
ALTER TABLE managed_targets DROP COLUMN auto_renew;

COMMIT;
