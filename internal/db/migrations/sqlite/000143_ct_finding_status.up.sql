-- (SQLite)
-- Purpose: W24-19 CT findings triage. ct_findings was created at runtime by
-- ctmonitor.Store.EnsureSchema (W6-06); this migration makes a migrations-only
-- hub own the table too, with the triage columns:
--   resolution   '' | 'acknowledged' | 'known_issuer'  (how a finding was closed;
--                status stays open|acknowledged because SQLite cannot alter a
--                CHECK in place)
--   resolved_by / resolved_at   who and when (RFC 3339 text)
--   tenant       owning tenant; 'default' for every pre-existing row
-- A database whose table pre-dates this migration keeps it unchanged here:
-- CREATE TABLE IF NOT EXISTS is a no-op and EnsureSchema adds the columns
-- (SQLite has no ADD COLUMN IF NOT EXISTS).
-- Rollback pair: 000143_ct_finding_status.down.sql

CREATE TABLE IF NOT EXISTS ct_findings (
    id          TEXT PRIMARY KEY,
    domain      TEXT NOT NULL,
    common_name TEXT NOT NULL DEFAULT '',
    dns_names   TEXT NOT NULL DEFAULT '[]',
    issuer      TEXT NOT NULL DEFAULT '',
    serial      TEXT NOT NULL DEFAULT '',
    not_before  TEXT NOT NULL DEFAULT '',
    not_after   TEXT NOT NULL DEFAULT '',
    source      TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'open'
                CHECK (status IN ('open', 'acknowledged')),
    created_at  TEXT NOT NULL,
    resolution  TEXT NOT NULL DEFAULT '',
    resolved_by TEXT NOT NULL DEFAULT '',
    resolved_at TEXT NOT NULL DEFAULT '',
    tenant      TEXT NOT NULL DEFAULT 'default'
);
CREATE INDEX IF NOT EXISTS idx_ct_findings_domain ON ct_findings(domain, status);
