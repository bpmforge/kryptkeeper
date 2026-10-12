-- A01S-4 / FR-P70 (PostgreSQL): record which certificate template's
-- ssh_policy authorised each SSH certificate. Empty for rows issued before
-- the template was required.
-- Depends on: 000046
-- Rollback pair: 000070_ssh_certificates_template_id.down.sql

BEGIN;

ALTER TABLE ssh_certificates ADD COLUMN IF NOT EXISTS template_id TEXT NOT NULL DEFAULT '';

COMMIT;
