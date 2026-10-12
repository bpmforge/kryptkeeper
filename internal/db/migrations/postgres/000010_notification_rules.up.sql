-- Wave W10 (Postgres)
-- Purpose: per-channel alert rules for threshold-based certificate expiry notifications
-- Depends on: W1 (users)
-- Rollback pair: 000010_notification_rules.down.sql

BEGIN;

CREATE TABLE notification_rules (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name           TEXT NOT NULL,
    threshold_days INTEGER NOT NULL CHECK (threshold_days > 0),
    channel        TEXT NOT NULL CHECK (channel IN ('email', 'slack', 'pagerduty', 'webhook')),
    target         TEXT NOT NULL,
    enabled        BOOLEAN NOT NULL DEFAULT TRUE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_notif_rules_enabled ON notification_rules(enabled);
CREATE INDEX idx_notif_rules_channel ON notification_rules(channel);

COMMIT;
