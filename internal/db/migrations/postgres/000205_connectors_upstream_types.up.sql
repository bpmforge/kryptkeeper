-- W27-35 (PostgreSQL) — widen connectors.type for the digicert, scep, est and
-- wstep upstream connector types. The 000044 CHECK was inline and unnamed, so
-- Postgres named it connectors_type_check.
-- Depends on: 000044
-- Rollback pair: 000205_connectors_upstream_types.down.sql

BEGIN;

ALTER TABLE connectors DROP CONSTRAINT IF EXISTS connectors_type_check;
ALTER TABLE connectors ADD CONSTRAINT connectors_type_check
    CHECK (type IN ('internal', 'acme', 'digicert', 'scep', 'est', 'wstep'));

COMMIT;
