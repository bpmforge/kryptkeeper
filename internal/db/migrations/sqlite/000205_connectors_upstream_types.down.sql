PRAGMA foreign_keys=OFF;

BEGIN;

CREATE TABLE connectors_old (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    type           TEXT NOT NULL CHECK (type IN ('internal', 'acme')),
    config_json    TEXT NOT NULL DEFAULT '{}',
    credential_ref TEXT,
    tenant         TEXT NOT NULL DEFAULT 'default',
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);

-- Rows of the widened types cannot satisfy the old CHECK; drop them.
INSERT INTO connectors_old (id, name, type, config_json, credential_ref, tenant, created_at, updated_at)
SELECT id, name, type, config_json, credential_ref, tenant, created_at, updated_at
FROM connectors WHERE type IN ('internal', 'acme');

DROP TABLE connectors;
ALTER TABLE connectors_old RENAME TO connectors;
CREATE INDEX IF NOT EXISTS idx_connectors_tenant ON connectors(tenant);

COMMIT;

PRAGMA foreign_keys=ON;
