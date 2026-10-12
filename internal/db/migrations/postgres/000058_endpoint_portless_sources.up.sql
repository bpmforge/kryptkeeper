-- Purpose: allow port-less discovery endpoints to persist -- K8s-secret-
-- sourced mesh certificate sources (Istio/Linkerd) are identified by a K8s
-- object name ("namespace/secret-name"), not a network address, and have
-- no listening socket at all. Without this, endpoints.port's CHECK
-- (port BETWEEN 1 AND 65535, from 000003) rejects every mesh discovery
-- result outright (W19-22, found live on W19-09's kind UAT, 2026-09-11):
-- internal/discovery/servicemesh.go's meshEndpoint() sets Port=0 by design
-- for its k8s-tls-secret/istio-mesh/linkerd-mesh sources, and
-- upsertScanResults' one-transaction-per-sweep design meant that single
-- CHECK violation discarded the ENTIRE sweep, not just the offending row --
-- mesh discovery has never landed anything in inventory since it was wired
-- (W7-06/W12-04), for any real cluster, ever.
--
-- Port=0 now means "not a network listener." The protocol column's own
-- CHECK is widened in the same migration so the source kind is recorded
-- honestly (k8s-tls-secret/istio-mesh/linkerd-mesh, the exact tags
-- servicemesh.go already emits) rather than collapsed to 'other' --
-- discoveryProtocolOrDefault (discovery_db_provider.go) now passes these
-- three straight through instead of mapping them down.
-- Depends on: 000003 (CHECK originally declared here)
-- Rollback pair: 000058_endpoint_portless_sources.down.sql

ALTER TABLE endpoints DROP CONSTRAINT IF EXISTS endpoints_port_check;
ALTER TABLE endpoints ADD CONSTRAINT endpoints_port_check
    CHECK (port BETWEEN 0 AND 65535);

ALTER TABLE endpoints DROP CONSTRAINT IF EXISTS endpoints_protocol_check;
ALTER TABLE endpoints ADD CONSTRAINT endpoints_protocol_check
    CHECK (protocol IN ('tls', 'ldaps', 'imaps', 'smtps', 'pop3s',
                         'ftps', 'rdps', 'kubernetes', 'other',
                         'k8s-tls-secret', 'istio-mesh', 'linkerd-mesh'));
