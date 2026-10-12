CREATE TABLE IF NOT EXISTS pending_actions (
    id          TEXT PRIMARY KEY,
    action_type TEXT NOT NULL,
    params_json TEXT NOT NULL,
    proposed_by TEXT NOT NULL,
    rationale   TEXT,
    status      TEXT NOT NULL DEFAULT 'pending',
    approved_by TEXT,
    decided_at  TEXT,
    result_json TEXT,
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pending_actions_status ON pending_actions(status);
