-- Rollback pair of 000053.
ALTER TABLE endpoints DROP COLUMN recommended_install_mode;
ALTER TABLE endpoints DROP COLUMN server_tech;
