-- W32-10: ITSM framework. Connections to ticketing systems and the
-- idempotent event/ticket-link table that doubles as the backoff queue.
-- Rollback pair: 000300_itsm.down.sql

CREATE TABLE IF NOT EXISTS itsm_connections (
    id             TEXT PRIMARY KEY,
    kind           TEXT NOT NULL CHECK (kind IN ('servicenow','jira')),
    name           TEXT NOT NULL,
    base_url       TEXT NOT NULL,
    credential_ref TEXT NOT NULL,
    event_classes  TEXT NOT NULL DEFAULT '[]',
    enabled        INTEGER NOT NULL DEFAULT 1,
    tenant         TEXT NOT NULL DEFAULT 'default',
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS itsm_events (
    event_id        TEXT PRIMARY KEY,
    connection_id   TEXT NOT NULL REFERENCES itsm_connections(id),
    class           TEXT NOT NULL,
    fingerprint     TEXT NOT NULL DEFAULT '',
    payload         TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','created','resolved','failed')),
    ticket_key      TEXT NOT NULL DEFAULT '',
    ticket_url      TEXT NOT NULL DEFAULT '',
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT NOT NULL,
    last_error      TEXT NOT NULL DEFAULT '',
    recreated       INTEGER NOT NULL DEFAULT 0,
    tenant          TEXT NOT NULL DEFAULT 'default',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_itsm_events_due ON itsm_events(status, next_attempt_at);
CREATE INDEX IF NOT EXISTS idx_itsm_events_fingerprint ON itsm_events(fingerprint);
