-- Wave W24 (SQLite) (W24-04): per-target discovery scan schedule.
-- One row per scheduled target (env network target string or managed target
-- id); it exists once an interval override is set or the scheduler has run
-- the target. interval_seconds NULL = use KRYPTKEEPER_DISCOVERY_SCAN_INTERVAL.
-- Times are RFC3339 UTC text.
-- Rollback pair: 000140_discovery_target_schedule.down.sql

CREATE TABLE IF NOT EXISTS discovery_target_schedules (
    target_key       TEXT PRIMARY KEY,
    scan_type        TEXT NOT NULL,
    target           TEXT NOT NULL,
    interval_seconds INTEGER CHECK (interval_seconds IS NULL OR interval_seconds >= 60),
    last_run_at      TEXT,
    last_job_id      TEXT,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL
);
