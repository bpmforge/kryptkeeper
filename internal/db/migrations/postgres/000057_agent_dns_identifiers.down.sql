-- Rollback pair of 000057.
ALTER TABLE agent_tasks DROP COLUMN identifiers;
ALTER TABLE agent_inventory DROP COLUMN dns_names;
