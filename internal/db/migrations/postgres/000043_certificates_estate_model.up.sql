-- W11-01 (PostgreSQL) — V5/D-106 estate model.
-- Purpose: origin + management_state on every certificate; backfill from source.
-- Depends on: 000002 (certificates)
-- Rollback pair: 000043_certificates_estate_model.down.sql

BEGIN;

ALTER TABLE certificates ADD COLUMN origin TEXT NOT NULL DEFAULT 'internal'
    CHECK (origin IN ('internal', 'imported', 'discovered', 'synced'));
ALTER TABLE certificates ADD COLUMN management_state TEXT NOT NULL DEFAULT 'managed'
    CHECK (management_state IN ('managed', 'external', 'unmanaged'));
UPDATE certificates SET origin = 'imported', management_state = 'unmanaged'
    WHERE source = 'import';

COMMIT;
