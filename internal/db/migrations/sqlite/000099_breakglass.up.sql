-- W22-37: break-glass activations (two-person, time-boxed) and the 24 h
-- after-action review tasks their use opens. Identical on both engines
-- (CREATE IF NOT EXISTS: the store also self-heals this DDL).
-- Rollback pair: 000099_breakglass.down.sql
CREATE TABLE IF NOT EXISTS breakglass_activations (
    id TEXT PRIMARY KEY,
    reason TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    requested_by TEXT NOT NULL DEFAULT '',
    confirmed_by TEXT NOT NULL DEFAULT '',
    requested_at TEXT NOT NULL DEFAULT '',
    activated_at TEXT NOT NULL DEFAULT '',
    expires_at TEXT NOT NULL DEFAULT ''
);

-- activation_id holds the review scope: "act-<activation id>" or "local-login".
-- actors is a JSON array of the principals whose use opened/extended the review
-- (a reviewer may not be one of them).
CREATE TABLE IF NOT EXISTS breakglass_reviews (
    id TEXT PRIMARY KEY,
    activation_id TEXT NOT NULL,
    status TEXT NOT NULL,
    opened_at TEXT NOT NULL DEFAULT '',
    due_at TEXT NOT NULL DEFAULT '',
    completed_by TEXT NOT NULL DEFAULT '',
    completed_at TEXT NOT NULL DEFAULT '',
    outcome TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    use_count INTEGER NOT NULL DEFAULT 0,
    actors TEXT NOT NULL DEFAULT '[]'
);

-- At most one OPEN review per scope, enforced by the database so two
-- concurrent first uses cannot open two tasks.
CREATE UNIQUE INDEX IF NOT EXISTS breakglass_reviews_one_open_per_scope
    ON breakglass_reviews (activation_id) WHERE status = 'open';
