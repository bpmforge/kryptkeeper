-- W11-01 (V5/D-106): the estate model. Every certificate carries where it
-- came from (origin) and who manages it (management_state). `source` stays
-- untouched for wire compat and seeds the backfill.
ALTER TABLE certificates ADD COLUMN origin TEXT NOT NULL DEFAULT 'internal'
    CHECK (origin IN ('internal', 'imported', 'discovered', 'synced'));
ALTER TABLE certificates ADD COLUMN management_state TEXT NOT NULL DEFAULT 'managed'
    CHECK (management_state IN ('managed', 'external', 'unmanaged'));
UPDATE certificates SET origin = 'imported', management_state = 'unmanaged'
    WHERE source = 'import';
