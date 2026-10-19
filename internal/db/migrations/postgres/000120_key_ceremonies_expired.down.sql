-- Rollback pair of 000120. `expired` has no representation under the old
-- CHECK; expired ceremonies are the same terminal outcome as aborted.

BEGIN;

UPDATE key_ceremonies SET status = 'aborted' WHERE status = 'expired';
ALTER TABLE key_ceremonies DROP CONSTRAINT IF EXISTS key_ceremonies_status_check;
ALTER TABLE key_ceremonies ADD CONSTRAINT key_ceremonies_status_check
    CHECK (status IN ('pending', 'completed', 'aborted'));
ALTER TABLE key_ceremonies DROP COLUMN IF EXISTS reminder_sent_at;

COMMIT;
