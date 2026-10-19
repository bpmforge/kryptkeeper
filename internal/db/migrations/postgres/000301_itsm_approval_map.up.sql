-- W32-12: approval via ITSM ticket. A link ties an approval-pending ticket to
-- the Kryptkeeper approval it decides; the principal map names which hub user
-- an external ITSM approver acts as. Rollback pair: 000301_itsm_approval_map.down.sql

CREATE TABLE IF NOT EXISTS itsm_approval_links (
    event_id    TEXT PRIMARY KEY REFERENCES itsm_events(event_id),
    approval_id TEXT NOT NULL,
    ticket_key  TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'waiting' CHECK (status IN ('waiting','approved','refused','done')),
    decided_at  TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_itsm_approval_links_status ON itsm_approval_links(status);

CREATE TABLE IF NOT EXISTS itsm_principal_map (
    external_id TEXT NOT NULL,
    kind        TEXT NOT NULL CHECK (kind IN ('servicenow','jira')),
    user_id     TEXT NOT NULL,
    tenant      TEXT NOT NULL DEFAULT 'default',
    PRIMARY KEY (kind, external_id)
);
