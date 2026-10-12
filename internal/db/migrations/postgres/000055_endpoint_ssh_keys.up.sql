-- Purpose: persist an SSH endpoint's banner and advertised host-key
-- algorithms. Discovery reads them (the scanner's ScanSSH), but nothing
-- stored them, so the SSH half of discovery — the host-key material that
-- feeds algorithm-sunset/PQC tracking — was captured and dropped. Nullable,
-- populated on the next scan.
-- Depends on: 000003
-- Rollback pair: 000055_endpoint_ssh_keys.down.sql

ALTER TABLE endpoints ADD COLUMN ssh_banner TEXT;
ALTER TABLE endpoints ADD COLUMN ssh_host_key_algorithms TEXT;
