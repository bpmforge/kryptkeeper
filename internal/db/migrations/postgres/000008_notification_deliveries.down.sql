-- Wave W8 rollback (PostgreSQL)
-- Drops notification_deliveries table

BEGIN;

DROP TABLE IF EXISTS notification_deliveries;

COMMIT;
