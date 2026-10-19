-- (sqlite) n-of-m approvals on pending actions (W22-10). quorum_n/quorum_m are
-- stamped at proposal time from the per-class policy; 1/1 is the legacy
-- single-approver behaviour. The approvals table is keyed by the canonical
-- HUMAN, not the credential, so one person holding several keys counts once.
ALTER TABLE pending_actions ADD COLUMN quorum_n INTEGER NOT NULL DEFAULT 1;
ALTER TABLE pending_actions ADD COLUMN quorum_m INTEGER NOT NULL DEFAULT 1;
CREATE TABLE IF NOT EXISTS pending_action_approvals (
    action_id TEXT NOT NULL, human TEXT NOT NULL, approver_id TEXT NOT NULL,
    created_at TEXT NOT NULL, PRIMARY KEY (action_id, human));
