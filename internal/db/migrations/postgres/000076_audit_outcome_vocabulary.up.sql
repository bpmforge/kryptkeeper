-- rc.7: audit_log.outcome CHECK only allowed success/failure/denied (and the
-- column was VARCHAR(10), too short for pending_approval/issuance_failed), but
-- the hub records skipped, pending_approval, proposed, executed,
-- issuance_failed and partial too; spiffe.workload_attest writes actor_type
-- 'workload'. Since the DB became the default audit store (RC1 H1) every such
-- append failed and was only logged: silent audit loss. Widens the column and
-- both CHECKs to the full AuditOutcome vocabulary
-- (internal/bootstrap/audit_outcome.go; audit_outcome_test.go keeps them in sync).
-- No rows are touched. On the partitioned parent the constraints propagate to
-- every partition.

BEGIN;

ALTER TABLE audit_log DROP CONSTRAINT IF EXISTS audit_log_outcome_check;
ALTER TABLE audit_log DROP CONSTRAINT IF EXISTS audit_log_actor_type_check;

ALTER TABLE audit_log ALTER COLUMN outcome TYPE VARCHAR(32);

ALTER TABLE audit_log ADD CONSTRAINT audit_log_outcome_check
    CHECK (outcome IN ('success', 'failure', 'denied', 'skipped', 'pending_approval', 'proposed', 'executed', 'issuance_failed', 'partial'));
ALTER TABLE audit_log ADD CONSTRAINT audit_log_actor_type_check
    CHECK (actor_type IN ('user', 'api_key', 'system', 'agent', 'workload'));

COMMIT;
