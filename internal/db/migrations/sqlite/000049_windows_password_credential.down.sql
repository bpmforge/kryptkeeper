-- Wave W18 (SQLite)
-- Purpose: rollback of 000049 -- restore the 000029 credential_type CHECK.
--
-- WinRM authenticates with a username and password (optionally an NTLM
-- domain). outbound_credentials only admitted ssh_key, api_token and
-- cloud_iam, so a Windows target could not resolve a credential at all --
-- the first blocker under every other W18 ticket.
--
-- SQLite has no ALTER TABLE ... DROP CONSTRAINT, so this uses the rebuild
-- dance (000042's pattern). The column list below is the table's CURRENT
-- shape: 000029 created it and NOTHING has altered it since (000044 and
-- 000045 only mention it in comments -- verified, no ALTER, no FK
-- REFERENCES). That check is the W17-11 lesson: a rebuild copying a stale
-- column list silently drops whatever was added later.
-- Depends on: 000029
-- NOTE: any existing windows_password row violates the restored CHECK and
-- the copy fails. Deliberate: a rollback must not silently retype a
-- credential. Remove Windows credentials first.
-- Pairs with: 000049_windows_password_credential.up.sql

PRAGMA foreign_keys=OFF;

BEGIN;

CREATE TABLE outbound_credentials_new (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    credential_type TEXT NOT NULL
                    CHECK (credential_type IN ('ssh_key', 'api_token', 'cloud_iam')),
    tenant          TEXT NOT NULL DEFAULT 'default',
    envelope        TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

INSERT INTO outbound_credentials_new
    (id, name, credential_type, tenant, envelope, created_at, updated_at)
SELECT
     id, name, credential_type, tenant, envelope, created_at, updated_at
FROM outbound_credentials;

DROP TABLE outbound_credentials;

ALTER TABLE outbound_credentials_new RENAME TO outbound_credentials;

CREATE INDEX IF NOT EXISTS idx_outbound_credentials_tenant ON outbound_credentials(tenant);

COMMIT;

PRAGMA foreign_keys=ON;
