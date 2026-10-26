-- W40-03 (D-319): per-agent outcome of a trust bundle (applied,
-- refused_not_opted_in, failed).
-- Rollback pair: 000372_trust_bundle_results.down.sql
BEGIN;

CREATE TABLE IF NOT EXISTS trust_bundle_results (
    bundle_id   TEXT NOT NULL,
    agent_id    TEXT NOT NULL,
    outcome     TEXT NOT NULL,
    detail      TEXT NOT NULL DEFAULT '',
    reported_at TEXT NOT NULL,
    PRIMARY KEY (bundle_id, agent_id)
);
CREATE INDEX IF NOT EXISTS idx_trust_bundle_results_agent ON trust_bundle_results(agent_id);

COMMIT;
