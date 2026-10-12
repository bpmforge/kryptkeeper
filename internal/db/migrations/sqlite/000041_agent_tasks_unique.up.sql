-- Prevents submitInventory (agent_store_db.go) and RenewalAgentDriver's
-- sweepAgentRenewals (renewal_agent_driver.go, W4-05) from both assigning an
-- AgentRenewalTask for the same (agent_id, fingerprint): their two
-- independent transactions can each read "no existing task" for a
-- newly-eligible cert before either commits -- matchRenewalTasks's own
-- no-duplicate guarantee only holds within a single existingTasks snapshot,
-- not across two concurrent transactions. insertTaskTx now inserts with
-- ON CONFLICT (agent_id, fingerprint) DO NOTHING, which needs this index to
-- have something to conflict on.
--
-- Any duplicate rows a database already accumulated from that race (real,
-- possible before this index existed) are collapsed to one arbitrary
-- survivor per (agent_id, fingerprint) pair first -- a bare CREATE UNIQUE
-- INDEX would otherwise abort this migration's transaction on any database
-- already holding one. Plain ANSI SQL (subquery + GROUP BY + MIN), not
-- engine-specific self-join/rowid syntax, so this file is identical to the
-- postgres version.
DELETE FROM agent_tasks WHERE task_id NOT IN
    (SELECT MIN(task_id) FROM agent_tasks GROUP BY agent_id, fingerprint);

CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_tasks_agent_fingerprint
    ON agent_tasks (agent_id, fingerprint);
