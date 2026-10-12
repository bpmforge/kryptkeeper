-- (PostgreSQL)
-- Purpose: add 'wstep' to certificates.source's CHECK constraint so
-- WSTEP-issued certificates can be recorded in the inventory (and therefore
-- reconstructed from it), as every other issuing protocol already is.
-- Until now internal/wstep issued without calling RecordIssuedCertificate
-- at all, so WSTEP issuance left no trace in the certificates table.
--
-- Body copied from 000060_certificates_source_vocabulary with one value
-- added; see 000060 for why the constraint is rebuilt the way it is.
-- Version 000064, not 000062/000063: those are taken by unmerged branches
-- (ssh_keys, credential_privileged), and a duplicate version would silently
-- overwrite a schema_migrations row. Gaps are expected (see CLAUDE.md).
--
-- Final vocabulary: 'api', 'acme', 'est', 'scep', 'cmp', 'tls-listener', 'wstep',
-- 'discovery_network', 'discovery_ssh', 'discovery_winrm', 'discovery_agent',
-- 'discovery_cloud', 'discovery_k8s', 'ct_log', 'import'.
-- Depends on: 000060
-- Rollback pair: 000064_certificates_source_wstep.down.sql
BEGIN;

ALTER TABLE certificates DROP CONSTRAINT IF EXISTS certificates_source_check;
ALTER TABLE certificates ADD CONSTRAINT certificates_source_check
    CHECK (source IN ('api', 'acme', 'est', 'scep', 'cmp', 'tls-listener', 'wstep',
                       'discovery_network', 'discovery_ssh', 'discovery_winrm',
                       'discovery_agent', 'discovery_cloud', 'discovery_k8s',
                       'ct_log', 'import'));

COMMIT;
