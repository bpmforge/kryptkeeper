-- Rollback pair of 000343.
ALTER TABLE outbound_credentials DROP COLUMN privileged_set_at;
ALTER TABLE outbound_credentials DROP COLUMN privileged_set_by;
ALTER TABLE outbound_credentials DROP COLUMN privileged_reason;
ALTER TABLE outbound_credentials DROP COLUMN privileged;
