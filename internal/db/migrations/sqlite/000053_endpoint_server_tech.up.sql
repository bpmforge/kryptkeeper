-- Purpose: record the web/server technology fingerprint and the install
-- mode it implies on each discovered endpoint (server_tech,
-- recommended_install_mode). Discovery now reads the HTTP Server header
-- over TLS and classifies the service protocol, so the estate knows a
-- Windows host runs Apache vs IIS and can recommend the right renewal
-- automation rather than assuming one. Nullable, no backfill — populated
-- on the next scan.
-- Depends on: 000003
-- Rollback pair: 000053_endpoint_server_tech.down.sql

ALTER TABLE endpoints ADD COLUMN server_tech TEXT;
ALTER TABLE endpoints ADD COLUMN recommended_install_mode TEXT;
