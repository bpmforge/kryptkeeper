-- W38-02 rollback (Postgres)
-- Purpose: restore the pre-plugin channel CHECK (itsm still allowed). plugin rows would violate it, so they are removed first.
-- Pair of: 000380_notification_plugin_channel.up.sql

BEGIN;

DELETE FROM notification_deliveries WHERE channel = 'plugin';
DELETE FROM notification_rules WHERE channel = 'plugin';

ALTER TABLE notification_rules DROP CONSTRAINT IF EXISTS notification_rules_channel_check;
ALTER TABLE notification_rules ADD CONSTRAINT notification_rules_channel_check
    CHECK (channel IN ('email', 'slack', 'pagerduty', 'webhook', 'itsm'));
ALTER TABLE notification_deliveries DROP CONSTRAINT IF EXISTS notification_deliveries_channel_check;
ALTER TABLE notification_deliveries ADD CONSTRAINT notification_deliveries_channel_check
    CHECK (channel IN ('email', 'slack', 'pagerduty', 'webhook', 'itsm'));

COMMIT;
