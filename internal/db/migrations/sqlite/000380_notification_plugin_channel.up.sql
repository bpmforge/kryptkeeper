-- W38-02 (SQLite)
-- Purpose: allow the 'plugin' channel in notification_rules and notification_deliveries (a rule routes to a
-- notify plugin with target <plugin_id>/<credential_id>, D-321). SQLite cannot alter a CHECK, so both tables
-- are rebuilt (000302 pattern), keeping every column, index and row.
-- Rollback pair: 000380_notification_plugin_channel.down.sql

PRAGMA foreign_keys=OFF;

BEGIN;

CREATE TABLE notification_rules_new (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    threshold_days INTEGER NOT NULL CHECK (threshold_days > 0),
    channel        TEXT NOT NULL CHECK (channel IN ('email', 'slack', 'pagerduty', 'webhook', 'itsm', 'plugin')),
    target         TEXT NOT NULL,
    enabled        INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    tenant         TEXT NOT NULL DEFAULT ''
);
INSERT INTO notification_rules_new (id, name, threshold_days, channel, target, enabled, created_at, updated_at, tenant)
SELECT id, name, threshold_days, channel, target, enabled, created_at, updated_at, tenant FROM notification_rules;
DROP TABLE notification_rules;
ALTER TABLE notification_rules_new RENAME TO notification_rules;
CREATE INDEX idx_notif_rules_enabled ON notification_rules(enabled);
CREATE INDEX idx_notif_rules_channel ON notification_rules(channel);

CREATE TABLE notification_deliveries_new (
    id                        TEXT PRIMARY KEY,
    notification_policy_id    TEXT REFERENCES notification_policies(id),
    channel                   TEXT NOT NULL
                              CHECK (channel IN ('email', 'slack', 'pagerduty', 'webhook', 'itsm', 'plugin')),
    target                    TEXT NOT NULL,
    subject                   TEXT,
    message                   TEXT,
    status                    TEXT NOT NULL DEFAULT 'queued'
                              CHECK (status IN ('queued', 'sending', 'sent', 'failed',
                                                'acknowledged', 'retrying')),
    error_detail              TEXT,
    retry_of_id               TEXT REFERENCES notification_deliveries(id),
    triggered_by              TEXT NOT NULL DEFAULT 'system',
    created_by                TEXT REFERENCES users(id),
    queued_at                 TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    delivered_at              TEXT,
    acknowledged_at           TEXT,
    acknowledged_by           TEXT,
    acknowledged_note         TEXT,
    created_at                TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
INSERT INTO notification_deliveries_new (id, notification_policy_id, channel, target, subject, message, status,
    error_detail, retry_of_id, triggered_by, created_by, queued_at, delivered_at, acknowledged_at,
    acknowledged_by, acknowledged_note, created_at)
SELECT id, notification_policy_id, channel, target, subject, message, status,
    error_detail, retry_of_id, triggered_by, created_by, queued_at, delivered_at, acknowledged_at,
    acknowledged_by, acknowledged_note, created_at FROM notification_deliveries;
DROP TABLE notification_deliveries;
ALTER TABLE notification_deliveries_new RENAME TO notification_deliveries;
CREATE INDEX idx_notif_delivery_status ON notification_deliveries(status);
CREATE INDEX idx_notif_delivery_channel ON notification_deliveries(channel);
CREATE INDEX idx_notif_delivery_queued ON notification_deliveries(queued_at DESC);
CREATE INDEX idx_notif_delivery_policy ON notification_deliveries(notification_policy_id);
CREATE INDEX idx_notif_delivery_retry ON notification_deliveries(retry_of_id);

COMMIT;

PRAGMA foreign_keys=ON;
