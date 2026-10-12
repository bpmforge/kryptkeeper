-- A01S-4 / FR-P70: SSH certificates are issued against a certificate template
-- whose ssh_policy names the allowed principals; record which template
-- authorised each one. Empty for rows issued before the template was required.
-- The migration runner tolerates "duplicate column" (the handler's
-- ensureSchema may already have created the table with the column).
-- Rollback pair: 000070_ssh_certificates_template_id.down.sql

ALTER TABLE ssh_certificates ADD COLUMN template_id TEXT NOT NULL DEFAULT '';
