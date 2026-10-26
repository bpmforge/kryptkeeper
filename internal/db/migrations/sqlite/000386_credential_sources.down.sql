-- Rollback pair of 000386.
ALTER TABLE outbound_credentials DROP COLUMN source_ref;
ALTER TABLE outbound_credentials DROP COLUMN source_id;
ALTER TABLE outbound_credentials DROP COLUMN source;
DROP INDEX IF EXISTS idx_credential_sources_tenant;
DROP TABLE IF EXISTS credential_sources;
