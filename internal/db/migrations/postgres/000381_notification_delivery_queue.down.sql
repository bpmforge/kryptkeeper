-- Rollback of 000381_notification_delivery_queue.up.sql.
DROP INDEX IF EXISTS idx_notification_delivery_queue_due;
DROP TABLE IF EXISTS notification_delivery_queue;
