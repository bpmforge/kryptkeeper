-- W24-08: where on the scanned host a certificate was read from (agentless SSH
-- discovery). NULL for network-scanned links, which have no file path.
-- Plain ADD COLUMN: no table rebuild, no CHECK.
-- Rollback pair: 000145_certificate_endpoints_source_path.down.sql

ALTER TABLE certificate_endpoints ADD COLUMN IF NOT EXISTS source_path TEXT;
