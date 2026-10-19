-- Purpose: W34-08 (FR-P27). Install posture: every certificate, key and
-- keystore file an SSH scan found, who owns it, which service uses it and the
-- findings that follow (PRIVILEGED_INSTALL_PATH, SERVICE_RUNS_AS_ROOT,
-- KEY_WORLD_READABLE, HOME_DIR_KEYSTORE). Key files are described by stat
-- only; no key bytes are stored. findings is a JSON array in TEXT, the same
-- convention as risk_flags. A cert can live in several files on several hosts,
-- hence certificate_files. UNIQUE carries tenant so two tenants scanning one
-- address cannot overwrite each other.
-- managed_targets.renewal_privilege_required is set from posture and cleared
-- when a later scan sees every file standard.
-- Depends on: 000083 (tenant), managed_targets
-- Rollback pair: 000342_discovered_files.down.sql

CREATE TABLE IF NOT EXISTS discovered_files (
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
    observed_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant, host, path)
);
CREATE INDEX IF NOT EXISTS idx_discovered_files_host ON discovered_files(tenant, host);

CREATE TABLE IF NOT EXISTS certificate_files (
    certificate_fingerprint TEXT NOT NULL,
    file_id                 TEXT NOT NULL REFERENCES discovered_files(id) ON DELETE CASCADE,
    PRIMARY KEY (certificate_fingerprint, file_id)
);
CREATE INDEX IF NOT EXISTS idx_certificate_files_file ON certificate_files(file_id);

ALTER TABLE managed_targets ADD COLUMN IF NOT EXISTS renewal_privilege_required BOOLEAN NOT NULL DEFAULT FALSE;
