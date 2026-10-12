-- Wave W18 (PostgreSQL)
-- Purpose: admit credential_type 'windows_password' (W18-01).
--
-- WinRM authenticates with a username and password (optionally an NTLM
-- domain). outbound_credentials only admitted ssh_key, api_token and
-- cloud_iam, so a Windows target could not resolve a credential at all.
-- Depends on: 000029
-- Rollback pair: 000049_windows_password_credential.down.sql

BEGIN;

ALTER TABLE outbound_credentials
    DROP CONSTRAINT IF EXISTS outbound_credentials_credential_type_check;

ALTER TABLE outbound_credentials
    ADD CONSTRAINT outbound_credentials_credential_type_check
    CHECK (credential_type IN ('ssh_key', 'api_token', 'cloud_iam', 'windows_password'));

COMMIT;
