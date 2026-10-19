-- W32-33 (Postgres)
-- Purpose: allow the 'itsm' channel in notification_rules and notification_deliveries.
-- Rollback pair: 000302_notification_itsm_channel.down.sql

BEGIN;

ALTER TABLE notification_rules DROP CONSTRAINT IF EXISTS notification_rules_channel_check;
ALTER TABLE notification_rules ADD CONSTRAINT notification_rules_channel_check
    CHECK (channel IN ('email', 'slack', 'pagerduty', 'webhook', 'itsm'));
ALTER TABLE notification_deliveries DROP CONSTRAINT IF EXISTS notification_deliveries_channel_check;
ALTER TABLE notification_deliveries ADD CONSTRAINT notification_deliveries_channel_check
    CHECK (channel IN ('email', 'slack', 'pagerduty', 'webhook', 'itsm'));

COMMIT;
