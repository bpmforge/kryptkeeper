-- Rollback pair of 000076. LOSSY-REFUSING: audit rows carrying an outcome or
-- actor_type introduced by 000076 cannot satisfy the original CHECK. The audit
-- log is append-only, so this rollback never deletes or rewrites them: it
-- raises (the transaction rolls back, every row intact) while any exist.

BEGIN;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM audit_log
         WHERE outcome NOT IN ('success', 'failure', 'denied')
            OR actor_type NOT IN ('user', 'api_key', 'system', 'agent')
    ) THEN
        RAISE EXCEPTION 'cannot roll back 000076: audit_log has rows that need the widened outcome/actor_type vocabulary and the audit log is append-only';
    END IF;
END $$;

ALTER TABLE audit_log DROP CONSTRAINT IF EXISTS audit_log_outcome_check;
ALTER TABLE audit_log DROP CONSTRAINT IF EXISTS audit_log_actor_type_check;

ALTER TABLE audit_log ALTER COLUMN outcome TYPE VARCHAR(10);

ALTER TABLE audit_log ADD CONSTRAINT audit_log_outcome_check
    CHECK (outcome IN ('success', 'failure', 'denied'));
ALTER TABLE audit_log ADD CONSTRAINT audit_log_actor_type_check
    CHECK (actor_type IN ('user', 'api_key', 'system', 'agent'));

COMMIT;
