-- W27-18: durable renewal failure queue. Scheduler execute failures and
-- notification dead letters live here so they survive a hub restart and appear
-- in GET /reports/renewal-slo failed_renewals with a type field.
-- Rollback pair: 000202_renewal_failure_queue.down.sql

CREATE TABLE IF NOT EXISTS renewal_failure_queue (
    id              TEXT PRIMARY KEY,
    kind            TEXT NOT NULL CHECK (kind IN ('execute_failure','notification_dead_letter')),
    fingerprint     TEXT NOT NULL,
    target_id       TEXT NOT NULL DEFAULT '',
    attempt         INTEGER NOT NULL DEFAULT 1,
    max_attempts    INTEGER NOT NULL DEFAULT 0,
    outcome         TEXT NOT NULL DEFAULT '',
    detail          TEXT NOT NULL DEFAULT '',
    gave_up         INTEGER NOT NULL DEFAULT 0 CHECK (gave_up IN (0, 1)),
    first_failed_at TEXT NOT NULL,
    last_failed_at  TEXT NOT NULL,
    next_attempt_at TEXT NOT NULL DEFAULT '',
    UNIQUE (kind, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_renewal_failure_queue_last ON renewal_failure_queue(last_failed_at);
