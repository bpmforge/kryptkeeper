-- W36-11 rollback: rows of the vendor types cannot satisfy the old CHECK and are dropped.
BEGIN;

DELETE FROM connectors WHERE type NOT IN ('internal', 'acme', 'digicert', 'scep', 'est', 'wstep');
ALTER TABLE connectors DROP CONSTRAINT IF EXISTS connectors_type_check;
ALTER TABLE connectors ADD CONSTRAINT connectors_type_check
    CHECK (type IN ('internal', 'acme', 'digicert', 'scep', 'est', 'wstep'));

COMMIT;
