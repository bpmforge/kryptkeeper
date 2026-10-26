-- W38-02 (Postgres)
-- Purpose: allow the 'plugin' channel in notification_rules and notification_deliveries (a rule routes to a
-- notify plugin with target <plugin_id>/<credential_id>, D-321).
-- Rollback pair: 000380_notification_plugin_channel.down.sql

BEGIN;

ALTER TABLE notification_rules DROP CONSTRAINT IF EXISTS notification_rules_channel_check;
ALTER TABLE notification_rules ADD CONSTRAINT notification_rules_channel_check
    CHECK (channel IN ('email', 'slack', 'pagerduty', 'webhook', 'itsm', 'plugin'));
ALTER TABLE notification_deliveries DROP CONSTRAINT IF EXISTS notification_deliveries_channel_check;
ALTER TABLE notification_deliveries ADD CONSTRAINT notification_deliveries_channel_check
    CHECK (channel IN ('email', 'slack', 'pagerduty', 'webhook', 'itsm', 'plugin'));

COMMIT;
