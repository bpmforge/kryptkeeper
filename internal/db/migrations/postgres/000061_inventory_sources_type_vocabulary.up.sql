-- Widen inventory_sources.type to every type validInventorySourceTypes
-- accepts; see the SQLite twin for the failure this fixes.
-- Depends on: 000045
-- Rollback pair: 000061_inventory_sources_type_vocabulary.down.sql

BEGIN;

ALTER TABLE inventory_sources DROP CONSTRAINT IF EXISTS inventory_sources_type_check;
ALTER TABLE inventory_sources ADD CONSTRAINT inventory_sources_type_check
    CHECK (type IN ('adcs_export', 'adcs_live', 'digicert', 'sectigo', 'entrust', 'aws_pca', 'gcp_cas'));

COMMIT;
