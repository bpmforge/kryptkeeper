-- Purpose: W34-09 (FR-P27). The agent's latest host pass (privilege mode,
-- unreadable paths, file posture), stored as JSON on the agent row so the agent
-- detail page can show INSUFFICIENT_PRIVILEGE with its count. NULL for an agent
-- that predates W34-09: its posture is unknown, never assumed standard.
-- ADD COLUMN IF NOT EXISTS: the agent store self-heals the same column.
-- Depends on: 000024
-- Rollback pair: 000346_agent_host_report.down.sql

ALTER TABLE agents ADD COLUMN IF NOT EXISTS host_report TEXT;
