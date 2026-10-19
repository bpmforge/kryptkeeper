-- Purpose: W34 (FR-R10). Accepted-risk exceptions can be filed against one
-- discovered file, so finding_exceptions.target_type admits 'target_file';
-- target_id is the discovered_files.id. Only the CHECK changes.
-- Depends on: 000022, 000342
-- Rollback pair: 000347_finding_exceptions_target_file.down.sql

ALTER TABLE finding_exceptions DROP CONSTRAINT IF EXISTS finding_exceptions_target_type_check;
ALTER TABLE finding_exceptions ADD CONSTRAINT finding_exceptions_target_type_check
    CHECK (target_type IN ('certificate', 'ca', 'target_file'));
