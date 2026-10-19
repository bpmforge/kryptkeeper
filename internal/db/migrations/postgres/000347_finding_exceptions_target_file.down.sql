-- Rollback pair of 000347. Exceptions on files go first: the narrower CHECK
-- cannot hold them. Their tenant stamps and lifecycle events are removed too.
DELETE FROM finding_exception_tenants WHERE exception_id IN (SELECT id FROM finding_exceptions WHERE target_type = 'target_file');
DELETE FROM finding_exception_events WHERE exception_id IN (SELECT id FROM finding_exceptions WHERE target_type = 'target_file');
DELETE FROM finding_exceptions WHERE target_type = 'target_file';
ALTER TABLE finding_exceptions DROP CONSTRAINT IF EXISTS finding_exceptions_target_type_check;
ALTER TABLE finding_exceptions ADD CONSTRAINT finding_exceptions_target_type_check
    CHECK (target_type IN ('certificate', 'ca'));
