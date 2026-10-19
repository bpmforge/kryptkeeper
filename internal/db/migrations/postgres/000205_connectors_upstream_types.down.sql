BEGIN;

-- Rows of the widened types cannot satisfy the old CHECK; remove them first.
DELETE FROM connectors WHERE type NOT IN ('internal', 'acme');
ALTER TABLE connectors DROP CONSTRAINT IF EXISTS connectors_type_check;
ALTER TABLE connectors ADD CONSTRAINT connectors_type_check
    CHECK (type IN ('internal', 'acme'));

COMMIT;
