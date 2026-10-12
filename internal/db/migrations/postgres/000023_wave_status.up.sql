-- Wave W2 (PostgreSQL)
-- Purpose: stored migration-wave lifecycle status (W2-08)
-- Depends on: W2 (migration_waves)
-- Rollback pair: 000023_wave_status.down.sql

BEGIN;

ALTER TABLE migration_waves ADD COLUMN status TEXT NOT NULL DEFAULT 'proposed';

COMMIT;
