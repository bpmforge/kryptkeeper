-- W23-07 (D-084/FR-P46): ceremonies idle past their TTL are auto-aborted into
-- the terminal `expired` state; reminder_sent_at records the 24h-before-expiry
-- approver reminder so it fires once and survives restarts.
-- Depends on: 000038
-- Rollback pair: 000120_key_ceremonies_expired.down.sql

BEGIN;

ALTER TABLE key_ceremonies DROP CONSTRAINT IF EXISTS key_ceremonies_status_check;
ALTER TABLE key_ceremonies ADD CONSTRAINT key_ceremonies_status_check
    CHECK (status IN ('pending', 'completed', 'aborted', 'expired'));
ALTER TABLE key_ceremonies ADD COLUMN IF NOT EXISTS reminder_sent_at TEXT;

COMMIT;
