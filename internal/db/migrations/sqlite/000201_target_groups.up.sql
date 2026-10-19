-- W27-04: fleet-level renewal policy. A named target group carries a renewal
-- threshold its members inherit unless they set their own; the scheduler
-- re-reads it every tick. Membership lives in its own table so managed_targets
-- is untouched. A target belongs to at most one group.
-- Rollback pair: 000201_target_groups.down.sql

CREATE TABLE IF NOT EXISTS target_groups (
    tenant                 TEXT NOT NULL DEFAULT 'default',
    name                   TEXT NOT NULL,
    renewal_threshold_days INTEGER NOT NULL CHECK (renewal_threshold_days BETWEEN 1 AND 398),
    created_at             TEXT NOT NULL,
    updated_at             TEXT NOT NULL,
    PRIMARY KEY (tenant, name)
);

CREATE TABLE IF NOT EXISTS target_group_members (
    target_id  TEXT PRIMARY KEY,
    tenant     TEXT NOT NULL,
    group_name TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tgm_group ON target_group_members(tenant, group_name);
