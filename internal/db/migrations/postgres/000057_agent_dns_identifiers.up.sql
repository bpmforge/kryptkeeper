-- Purpose: W19-13. AgentRenewalTask.Subject was a full pkix.Name RDN string
-- (e.g. "CN=localhost"), and the agent's ACME renewer used it verbatim as
-- the DNS identifier in the order -- which can never satisfy an HTTP-01
-- challenge (UAT W19-04, 2026-09-10). agent_inventory.dns_names carries the
-- discovered certificate's SAN list as reported by the agent (JSON array,
-- empty for pre-W19-13 agents that don't report it); agent_tasks.identifiers
-- carries the DNS identifiers the hub computed for that task (SANs first,
-- then a CN fallback if it parses as a hostname) so a restart-safe DB round
-- trip doesn't lose them. Both nullable/defaulted so no backfill is needed --
-- an old row with no dns_names still yields identifiers by parsing its
-- subject's CN at read time (agent-side fallback), never by using the raw
-- RDN string as an identifier.
-- Depends on: 000015, 000041
-- Rollback pair: 000057_agent_dns_identifiers.down.sql

ALTER TABLE agent_inventory ADD COLUMN dns_names TEXT NOT NULL DEFAULT '[]';
ALTER TABLE agent_tasks ADD COLUMN identifiers TEXT NOT NULL DEFAULT '[]';
