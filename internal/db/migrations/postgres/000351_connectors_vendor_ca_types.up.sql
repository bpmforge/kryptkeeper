-- W36-11: widen connectors.type for the vendor CA connector types (vault_pki, ejbca, aws_pca, gcp_cas, sectigo, globalsign, entrust).
-- Depends on: 000205
-- Rollback pair: 000351_connectors_vendor_ca_types.down.sql
BEGIN;

ALTER TABLE connectors DROP CONSTRAINT IF EXISTS connectors_type_check;
ALTER TABLE connectors ADD CONSTRAINT connectors_type_check
    CHECK (type IN ('internal', 'acme', 'digicert', 'scep', 'est', 'wstep', 'vault_pki', 'ejbca', 'aws_pca', 'gcp_cas', 'sectigo', 'globalsign', 'entrust'));

COMMIT;
