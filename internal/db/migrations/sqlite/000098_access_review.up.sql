-- W22-35: access recertification campaigns. A campaign snapshots the access
-- review report at open time; decisions are per snapshot entry. Identical on
-- both engines (CREATE IF NOT EXISTS: the store also self-heals this DDL).
-- Rollback pair: 000098_access_review.down.sql
CREATE TABLE IF NOT EXISTS access_review_campaigns (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    period_start TEXT NOT NULL,
    period_end TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    opened_by TEXT NOT NULL,
    opened_at TEXT NOT NULL,
    closed_by TEXT NOT NULL DEFAULT '',
    closed_at TEXT NOT NULL DEFAULT '',
    report_sha256 TEXT NOT NULL DEFAULT '',
    snapshot_json TEXT NOT NULL,
    tenant TEXT NOT NULL DEFAULT 'default'
);

CREATE TABLE IF NOT EXISTS access_review_decisions (
    campaign_id TEXT NOT NULL,
    entry_id TEXT NOT NULL,
    decision TEXT NOT NULL,
    new_role TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL DEFAULT '',
    decided_by TEXT NOT NULL,
    decided_at TEXT NOT NULL,
    second_reviewer TEXT NOT NULL DEFAULT '',
    executed INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (campaign_id, entry_id)
);
