-- Wave 19 rollback (PostgreSQL)
-- Paired with: 000060_certificates_source_vocabulary.up.sql
--
-- Restores the pre-W19-33 source vocabulary (no 'cmp' or 'tls-listener').
-- Unlike the up migration, ADD CONSTRAINT here validates every existing
-- row, so this rollback fails loudly (not silently) if a 'cmp' or
-- 'tls-listener' certificate was written while the wider constraint was
-- active -- the operator must reclassify or remove those rows first.
-- Depends on: 000002

BEGIN;

ALTER TABLE certificates DROP CONSTRAINT IF EXISTS certificates_source_check;
ALTER TABLE certificates ADD CONSTRAINT certificates_source_check
    CHECK (source IN ('api', 'acme', 'est', 'scep', 'discovery_network',
                       'discovery_ssh', 'discovery_winrm', 'discovery_agent',
                       'discovery_cloud', 'discovery_k8s', 'ct_log', 'import'));

COMMIT;
