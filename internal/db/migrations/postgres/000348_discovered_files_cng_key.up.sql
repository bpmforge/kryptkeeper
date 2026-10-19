-- Purpose: W34-12 (FR-P27). Windows install posture lists private-key
-- container files (CNG/CAPI) next to certificates, so discovered_files.kind
-- admits 'cng_key'. Only the CHECK changes.
-- Depends on: 000342
-- Rollback pair: 000348_discovered_files_cng_key.down.sql

ALTER TABLE discovered_files DROP CONSTRAINT IF EXISTS discovered_files_kind_check;
ALTER TABLE discovered_files ADD CONSTRAINT discovered_files_kind_check
    CHECK (kind IN ('pem', 'jks', 'p12', 'key', 'config', 'cng_key'));
