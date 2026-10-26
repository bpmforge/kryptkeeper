-- W40-03 (D-318): hub trust bundles, CA certificates pushed to agents' OS trust
-- stores. A row exists only once the dual-control approval has executed.
-- Rollback pair: 000371_trust_bundles.down.sql
BEGIN;

CREATE TABLE IF NOT EXISTS trust_bundles (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    action         TEXT NOT NULL,
    cert_pem       TEXT NOT NULL,
    certs_json     TEXT NOT NULL,
    selector_json  TEXT NOT NULL,
    agent_ids_json TEXT NOT NULL,
    created_by     TEXT NOT NULL,
    approved_by    TEXT NOT NULL,
    action_id      TEXT NOT NULL,
    created_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_trust_bundles_created ON trust_bundles(created_at);

COMMIT;
