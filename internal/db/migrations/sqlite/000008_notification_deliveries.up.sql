-- Wave W8 (SQLite)
-- Purpose: notification delivery log for WS-07
-- Depends on: W1 (notification_policies, users)
-- Rollback pair: 000008_notification_deliveries.down.sql

BEGIN;

CREATE TABLE notification_deliveries (
    id                        TEXT PRIMARY KEY,
    notification_policy_id    TEXT REFERENCES notification_policies(id),
    channel                   TEXT NOT NULL
                              CHECK (channel IN ('email', 'slack', 'pagerduty', 'webhook')),
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

CREATE INDEX idx_notif_delivery_status ON notification_deliveries(status);
CREATE INDEX idx_notif_delivery_channel ON notification_deliveries(channel);
CREATE INDEX idx_notif_delivery_queued ON notification_deliveries(queued_at DESC);
CREATE INDEX idx_notif_delivery_policy ON notification_deliveries(notification_policy_id);
CREATE INDEX idx_notif_delivery_retry ON notification_deliveries(retry_of_id);

-- Seed data for CI/test
INSERT INTO notification_deliveries (id, channel, target, subject, message, status, triggered_by, queued_at)
VALUES
    ('00000000-0000-0000-0000-000000000201', 'email', 'ops@example.com', 'Certificate expiring', 'Certificate fp-safe expires in 30 days', 'failed', 'threshold', '2026-04-07T03:00:00Z'),
    ('00000000-0000-0000-0000-000000000202', 'slack', '#pki-alerts', 'Scan complete', 'Network scan completed', 'sent', 'scan_complete', '2026-04-07T02:00:00Z'),
    ('00000000-0000-0000-0000-000000000203', 'email', 'security@example.com', 'Risk alert', 'High risk endpoint detected', 'queued', 'risk_alert', '2026-04-07T01:00:00Z');

COMMIT;
