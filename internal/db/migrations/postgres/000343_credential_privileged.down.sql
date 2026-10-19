-- Rollback pair of 000343.
ALTER TABLE outbound_credentials DROP COLUMN IF EXISTS privileged_set_at;
ALTER TABLE outbound_credentials DROP COLUMN IF EXISTS privileged_set_by;
ALTER TABLE outbound_credentials DROP COLUMN IF EXISTS privileged_reason;
ALTER TABLE outbound_credentials DROP COLUMN IF EXISTS privileged;
