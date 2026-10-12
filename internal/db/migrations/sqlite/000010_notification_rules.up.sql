-- Wave W10 (SQLite)
-- Purpose: per-channel alert rules for threshold-based certificate expiry notifications
-- Depends on: W1 (users)
-- Rollback pair: 000010_notification_rules.down.sql

BEGIN;

CREATE TABLE notification_rules (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    threshold_days INTEGER NOT NULL CHECK (threshold_days > 0),
    channel        TEXT NOT NULL CHECK (channel IN ('email', 'slack', 'pagerduty', 'webhook')),
    target         TEXT NOT NULL,
    enabled        INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE INDEX idx_notif_rules_enabled ON notification_rules(enabled);
CREATE INDEX idx_notif_rules_channel ON notification_rules(channel);

COMMIT;
