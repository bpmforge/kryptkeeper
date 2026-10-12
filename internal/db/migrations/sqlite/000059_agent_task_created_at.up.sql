-- Purpose: W19-26. GET /api/v1/agents/{id}/tasks surfaces queued tasks and
-- their reported results as durable evidence (today the audit log is the
-- only record) -- that view needs a "when was this task queued" timestamp,
-- which agent_tasks never tracked. Nullable/defaulted so no backfill is
-- needed: a pre-existing row reads back as a zero time, same as any other
-- field this store already treats as "unknown" rather than failing the scan
-- (see scanTasks's identifiers handling for the established precedent).
-- Depends on: 000015, 000057
-- Rollback pair: 000059_agent_task_created_at.down.sql

ALTER TABLE agent_tasks ADD COLUMN created_at TEXT NOT NULL DEFAULT '';
