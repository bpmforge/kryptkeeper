-- Rollback pair of 000346.
ALTER TABLE agents DROP COLUMN IF EXISTS host_report;
