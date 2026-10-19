-- W29-06: per-agent single-use enrollment tokens (hash only; 24h default expiry).
-- Timestamps are RFC3339 UTC strings, matching the rest of the agent schema.
CREATE TABLE IF NOT EXISTS agent_enrollment_tokens (
  id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, label TEXT NOT NULL DEFAULT '',
  created_by TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
  redeemed_at TEXT NOT NULL DEFAULT '', redeemed_agent_id TEXT NOT NULL DEFAULT '',
  revoked_at TEXT NOT NULL DEFAULT '');
