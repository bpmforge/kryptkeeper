-- W36-11 rollback: rows of the vendor types cannot satisfy the old CHECK and are dropped.
PRAGMA foreign_keys=OFF;

BEGIN;

CREATE TABLE connectors_new (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    type           TEXT NOT NULL CHECK (type IN ('internal', 'acme', 'digicert', 'scep', 'est', 'wstep')),
    config_json    TEXT NOT NULL DEFAULT '{}',
    credential_ref TEXT,
    tenant         TEXT NOT NULL DEFAULT 'default',
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);

INSERT INTO connectors_new (id, name, type, config_json, credential_ref, tenant, created_at, updated_at)
SELECT id, name, type, config_json, credential_ref, tenant, created_at, updated_at
FROM connectors
WHERE type IN ('internal', 'acme', 'digicert', 'scep', 'est', 'wstep');

DROP TABLE connectors;
ALTER TABLE connectors_new RENAME TO connectors;
CREATE INDEX IF NOT EXISTS idx_connectors_tenant ON connectors(tenant);

COMMIT;

PRAGMA foreign_keys=ON;
