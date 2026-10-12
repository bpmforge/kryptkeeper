-- Wave W8 rollback (SQLite)
-- Drops notification_deliveries table

BEGIN;

DROP TABLE IF EXISTS notification_deliveries;

COMMIT;
