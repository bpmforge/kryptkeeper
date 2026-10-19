-- W32-33 rollback (Postgres)
-- Purpose: restore the pre-itsm channel CHECK. itsm rows would violate it, so they are removed first.
-- Pair of: 000302_notification_itsm_channel.up.sql

BEGIN;

DELETE FROM notification_deliveries WHERE channel = 'itsm';
DELETE FROM notification_rules WHERE channel = 'itsm';

ALTER TABLE notification_rules DROP CONSTRAINT IF EXISTS notification_rules_channel_check;
ALTER TABLE notification_rules ADD CONSTRAINT notification_rules_channel_check
    CHECK (channel IN ('email', 'slack', 'pagerduty', 'webhook'));
ALTER TABLE notification_deliveries DROP CONSTRAINT IF EXISTS notification_deliveries_channel_check;
ALTER TABLE notification_deliveries ADD CONSTRAINT notification_deliveries_channel_check
    CHECK (channel IN ('email', 'slack', 'pagerduty', 'webhook'));

COMMIT;
