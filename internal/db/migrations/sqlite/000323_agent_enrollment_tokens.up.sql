-- W33-24: extends W29-06's agent_enrollment_tokens (000240) instead of owning
-- a second table. Tokens are tenant-scoped: mint stamps the caller's tenant,
-- list/revoke filter on it. Pre-existing W29 rows land in the default tenant.
-- W33's other fields map onto W29 columns: name_hint -> label,
-- used_at -> redeemed_at, agent_id -> redeemed_agent_id (status is computed).
-- NOTE: a dev database that applied the earlier W33 draft of 000323 (its own
-- table layout) is not upgradable by this file; recreate that database.
ALTER TABLE agent_enrollment_tokens ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';
