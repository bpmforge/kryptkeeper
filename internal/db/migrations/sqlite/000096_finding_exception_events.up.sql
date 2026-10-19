-- (sqlite) Exception lifecycle events (W22-31): one row per (exception, kind)
-- claims the single expiry warning and the single lapse audit across restarts
-- and replicas. The primary key is the idempotency guard.
CREATE TABLE IF NOT EXISTS finding_exception_events (
    exception_id TEXT NOT NULL,
    kind         TEXT NOT NULL CHECK (kind IN ('expiring', 'expired')),
    at           TEXT NOT NULL,
    PRIMARY KEY (exception_id, kind)
);
