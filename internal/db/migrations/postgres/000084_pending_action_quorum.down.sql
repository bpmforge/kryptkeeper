DROP TABLE IF EXISTS pending_action_approvals;
ALTER TABLE pending_actions DROP COLUMN IF EXISTS quorum_m;
ALTER TABLE pending_actions DROP COLUMN IF EXISTS quorum_n;
