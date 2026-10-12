BEGIN;

DELETE FROM inventory_sources WHERE type NOT IN ('adcs_export', 'digicert');
ALTER TABLE inventory_sources DROP CONSTRAINT IF EXISTS inventory_sources_type_check;
ALTER TABLE inventory_sources ADD CONSTRAINT inventory_sources_type_check
    CHECK (type IN ('adcs_export', 'digicert'));

COMMIT;
