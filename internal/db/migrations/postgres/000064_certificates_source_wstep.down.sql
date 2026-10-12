-- (PostgreSQL)
-- Rollback for 000064: restore 000060's certificates.source vocabulary
-- (drops 'wstep'). Body identical to 000060's up migration.
-- Rows already recorded with source='wstep' must be removed or re-sourced
-- before this rollback, or the rebuilt constraint will reject them.
BEGIN;

ALTER TABLE certificates DROP CONSTRAINT IF EXISTS certificates_source_check;
ALTER TABLE certificates ADD CONSTRAINT certificates_source_check
    CHECK (source IN ('api', 'acme', 'est', 'scep', 'cmp', 'tls-listener',
                       'discovery_network', 'discovery_ssh', 'discovery_winrm',
                       'discovery_agent', 'discovery_cloud', 'discovery_k8s',
                       'ct_log', 'import'));

COMMIT;
