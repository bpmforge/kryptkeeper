-- W36-11 rollback: rows of the added types cannot satisfy the old CHECK and are dropped.
BEGIN;

DELETE FROM inventory_sources WHERE type NOT IN ('adcs_export', 'adcs_live', 'digicert', 'sectigo', 'entrust', 'aws_pca', 'gcp_cas');
ALTER TABLE inventory_sources DROP CONSTRAINT IF EXISTS inventory_sources_type_check;
ALTER TABLE inventory_sources ADD CONSTRAINT inventory_sources_type_check
    CHECK (type IN ('adcs_export', 'adcs_live', 'digicert', 'sectigo', 'entrust', 'aws_pca', 'gcp_cas'));

COMMIT;
