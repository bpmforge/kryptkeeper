-- W36-11: widen inventory_sources.type for globalsign, vault_pki and ejbca.
-- Depends on: 000061
-- Rollback pair: 000352_inventory_sources_vendor_types.down.sql
BEGIN;

ALTER TABLE inventory_sources DROP CONSTRAINT IF EXISTS inventory_sources_type_check;
ALTER TABLE inventory_sources ADD CONSTRAINT inventory_sources_type_check
    CHECK (type IN ('adcs_export', 'adcs_live', 'digicert', 'sectigo', 'entrust', 'aws_pca', 'gcp_cas', 'globalsign', 'vault_pki', 'ejbca'));

COMMIT;
