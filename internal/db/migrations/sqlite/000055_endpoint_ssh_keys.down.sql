-- Rollback pair of 000055.
ALTER TABLE endpoints DROP COLUMN ssh_host_key_algorithms;
ALTER TABLE endpoints DROP COLUMN ssh_banner;
