-- W32-31: durable retry state for every channel delivery. next_attempt_at is
-- persisted so a restart resumes pending retries; event_json holds the event
-- needed to resend (its target may embed a webhook credential, like the
-- notification rule that produced it).
-- Rollback pair: 000381_notification_delivery_queue.down.sql

CREATE TABLE IF NOT EXISTS notification_delivery_queue (
    id              TEXT PRIMARY KEY,
    channel         TEXT NOT NULL,
    event_json      TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'retrying' CHECK (status IN ('retrying','sent','failed')),
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT NOT NULL,
    last_error      TEXT NOT NULL DEFAULT '',
    updated_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_notification_delivery_queue_due
    ON notification_delivery_queue (status, next_attempt_at);
