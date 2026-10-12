CREATE TABLE IF NOT EXISTS evidence_schedules (
    id           TEXT PRIMARY KEY,
    framework    TEXT NOT NULL,
    cadence      TEXT NOT NULL,
    recipients   TEXT NOT NULL,
    enabled      INTEGER NOT NULL DEFAULT 1,
    last_sent_at TEXT,
    created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evidence_schedules_enabled ON evidence_schedules(enabled);
