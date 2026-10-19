CREATE TABLE IF NOT EXISTS report_schedules (
    id           TEXT PRIMARY KEY,
    report       TEXT NOT NULL,
    format       TEXT NOT NULL,
    cadence      TEXT NOT NULL,
    recipients   TEXT NOT NULL,
    enabled      INTEGER NOT NULL DEFAULT 1,
    last_sent_at TEXT,
    created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_report_schedules_enabled ON report_schedules(enabled);
