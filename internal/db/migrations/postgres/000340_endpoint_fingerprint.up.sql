-- Purpose: W34-01 (FR-P27). One fingerprint per discovered endpoint: the
-- technology behind it (tech), how sure the scan is (tech_confidence), the
-- host platform, the TLS stack and the evidence rows that voted, stored as
-- JSON text. server_tech is untouched and keeps being written for readers
-- that predate this; it equals tech when the tech is a web server.
-- endpoints.protocol is widened so database and broker endpoints can be
-- filtered on instead of collapsing into 'other'.
-- ADD COLUMN IF NOT EXISTS: a discovery-only data directory may already have
-- these columns from the provider's EnsureSchema.
-- Depends on: 000058 (protocol CHECK last widened)
-- Rollback pair: 000340_endpoint_fingerprint.down.sql

ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS tech TEXT;
ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS tech_confidence TEXT
    CHECK (tech_confidence IS NULL OR tech_confidence IN ('high', 'medium', 'low'));
ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS platform TEXT;
ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS tls_stack TEXT;
ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS tech_evidence TEXT;

ALTER TABLE endpoints DROP CONSTRAINT IF EXISTS endpoints_protocol_check;
ALTER TABLE endpoints ADD CONSTRAINT endpoints_protocol_check
    CHECK (protocol IN ('tls', 'ldaps', 'imaps', 'smtps', 'pop3s',
                         'ftps', 'rdps', 'kubernetes', 'other',
                         'k8s-tls-secret', 'istio-mesh', 'linkerd-mesh',
                         'mssql', 'mysql', 'oracle', 'redis', 'mongodb', 'kafka'));
