-- Wave 19 (PostgreSQL)
-- Purpose: widen certificates.source's CHECK constraint to the full set of
-- values the code actually writes (W19-33, found by the W19-31 protocols
-- fixture, 2026-09-11).
--
-- The vocabulary declared by 000002_templates_ca_certs_core was 'api',
-- 'acme', 'est', 'scep', 'discovery_network', 'discovery_ssh',
-- 'discovery_winrm', 'discovery_agent', 'discovery_cloud', 'discovery_k8s',
-- 'ct_log', 'import'. Two writers were never added to it:
--   - internal/cmp/server.go calls RecordIssuedCertificate(..., "cmp") for
--     every CMP-issued certificate (W18-18).
--   - cmd/kryptkeeper/tls.go's tlsListenerSource calls it with
--     "tls-listener" for the hub's self-issued listener certificate
--     (W19-21).
-- writeCertToDB's ON CONFLICT DO NOTHING swallows a CHECK violation exactly
-- like it swallows a duplicate-key no-op (see be8e187's fix for the
-- renewal case), so both writers silently failed to reach the certificates
-- table with no log line -- confirmed live via the CMP protocol fixture.
-- This migration adds 'cmp' and 'tls-listener' to the allowed set; W19-33
-- also makes writeCertToDB itself report a rejection as an error rather
-- than relying solely on the vocabulary being complete.
--
-- Final vocabulary: 'api', 'acme', 'est', 'scep', 'cmp', 'tls-listener',
-- 'discovery_network', 'discovery_ssh', 'discovery_winrm',
-- 'discovery_agent', 'discovery_cloud', 'discovery_k8s', 'ct_log', 'import'.
--
-- The constraint was declared inline in 000002's CREATE TABLE with no name,
-- so Postgres auto-named it certificates_source_check -- confirmed against
-- a disposable postgres:16-alpine container before writing this (same
-- verification 000042's postgres migration used for its FK names).
-- Depends on: 000002
-- Rollback pair: 000060_certificates_source_vocabulary.down.sql

BEGIN;

ALTER TABLE certificates DROP CONSTRAINT IF EXISTS certificates_source_check;
ALTER TABLE certificates ADD CONSTRAINT certificates_source_check
    CHECK (source IN ('api', 'acme', 'est', 'scep', 'cmp', 'tls-listener',
                       'discovery_network', 'discovery_ssh', 'discovery_winrm',
                       'discovery_agent', 'discovery_cloud', 'discovery_k8s',
                       'ct_log', 'import'));

COMMIT;
