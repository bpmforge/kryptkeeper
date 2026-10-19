-- Rollback pair of 000348. cng_key rows are derived from WinRM scans and are
-- rebuilt by the next one, so removing them loses no operator data.
DELETE FROM discovered_files WHERE kind = 'cng_key';

PRAGMA foreign_keys=OFF;

BEGIN;

CREATE TABLE discovered_files_old (
    id             TEXT PRIMARY KEY,
    tenant         TEXT NOT NULL DEFAULT '',
    target_id      TEXT,
    agent_id       TEXT,
    host           TEXT NOT NULL,
    path           TEXT NOT NULL,
    kind           TEXT NOT NULL CHECK (kind IN ('pem', 'jks', 'p12', 'key', 'config')),
    owner_uid      INTEGER,
    owner_gid      INTEGER,
    owner_name     TEXT,
    group_name     TEXT,
    mode           TEXT,
    service_tech   TEXT,
    service_uid    INTEGER,
    service_name   TEXT,
    posture        TEXT NOT NULL CHECK (posture IN ('standard', 'privileged', 'root_service', 'unknown')),
    findings       TEXT NOT NULL DEFAULT '[]',
    observed_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    UNIQUE (tenant, host, path)
);

INSERT INTO discovered_files_old
    (id, tenant, target_id, agent_id, host, path, kind, owner_uid, owner_gid, owner_name, group_name, mode,
     service_tech, service_uid, service_name, posture, findings, observed_at)
SELECT
     id, tenant, target_id, agent_id, host, path, kind, owner_uid, owner_gid, owner_name, group_name, mode,
     service_tech, service_uid, service_name, posture, findings, observed_at
FROM discovered_files;

DROP TABLE discovered_files;

ALTER TABLE discovered_files_old RENAME TO discovered_files;

CREATE INDEX IF NOT EXISTS idx_discovered_files_host ON discovered_files(tenant, host);

COMMIT;

PRAGMA foreign_keys=ON;
