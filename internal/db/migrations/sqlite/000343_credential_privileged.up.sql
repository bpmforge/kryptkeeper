-- Purpose: W34-11 (FR-P25, D-208). Outbound credentials carry a privileged
-- flag: the account is high-impact on the hosts it reaches (sudo ALL, uid 0,
-- or a raw allowlist with cat/install on broad globs). Set by the sudo
-- preflight or by hand; flag and audit only, no approval gate.
-- ADD COLUMN: the credential store self-heals the same columns.
-- Depends on: 000029
-- Rollback pair: 000343_credential_privileged.down.sql

ALTER TABLE outbound_credentials ADD COLUMN privileged INTEGER NOT NULL DEFAULT 0;
ALTER TABLE outbound_credentials ADD COLUMN privileged_reason TEXT;
ALTER TABLE outbound_credentials ADD COLUMN privileged_set_by TEXT;
ALTER TABLE outbound_credentials ADD COLUMN privileged_set_at TEXT;
