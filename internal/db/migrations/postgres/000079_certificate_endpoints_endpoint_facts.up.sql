-- (PostgreSQL)
-- Purpose: move endpoint-specific facts off the shared certificates row onto
-- the certificate<->endpoint link. One certificate can be served on several
-- endpoints; whether it matches the name, was served with its intermediate, or
-- chains to a trusted root differs per endpoint, and stored on the certificate
-- those verdicts flipped with whichever endpoint was scanned last.
--   endpoint_flags       JSON array (as text) of HOSTNAME_MISMATCH /
--                        INCOMPLETE_CHAIN / UNTRUSTED_ROOT observed at this
--                        endpoint.
--   endpoint_risk_score  summed weight of those flags; the risky-endpoint rule
--                        adds it to the certificate's own score.
--   chain_complete       NULL = completeness could not be judged for this
--                        endpoint; only a proven missing intermediate is FALSE.
--   chain_trusted        NULL = never classified.
-- Existing links start empty and are populated by the next scan of each
-- endpoint; a stale endpoint flag still on a certificate row is ignored by the
-- readers and cleared when that certificate is next scanned.
-- Depends on: 000003
-- Rollback pair: 000079_certificate_endpoints_endpoint_facts.down.sql

ALTER TABLE certificate_endpoints ADD COLUMN IF NOT EXISTS endpoint_flags TEXT NOT NULL DEFAULT '[]';
ALTER TABLE certificate_endpoints ADD COLUMN IF NOT EXISTS endpoint_risk_score INTEGER NOT NULL DEFAULT 0;
ALTER TABLE certificate_endpoints ADD COLUMN IF NOT EXISTS chain_complete BOOLEAN;
ALTER TABLE certificate_endpoints ADD COLUMN IF NOT EXISTS chain_trusted BOOLEAN;
