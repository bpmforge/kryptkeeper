CREATE TABLE IF NOT EXISTS posture_snapshots (
    id                  TEXT PRIMARY KEY,
    captured_at         TEXT NOT NULL,
    total_certs         INTEGER NOT NULL,
    pqc_score_percent   INTEGER NOT NULL,
    automation_percent  INTEGER NOT NULL,
    risk_critical       INTEGER NOT NULL,
    risk_high           INTEGER NOT NULL,
    risk_medium         INTEGER NOT NULL,
    risk_low            INTEGER NOT NULL,
    expired             INTEGER NOT NULL,
    expiring_47d        INTEGER NOT NULL,
    report_json         TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_posture_snapshots_captured ON posture_snapshots(captured_at);
