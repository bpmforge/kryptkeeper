-- Wave S (PostgreSQL)
-- Purpose: drop certificates.template_id and certificates.team_id's FOREIGN
-- KEY constraints, and widen both columns from UUID to TEXT (S-51). Neither
-- referenced table is authoritative in a default install:
-- certificate_templates is file-backed (APP_TEMPLATE_PROVIDER) and its IDs
-- look like "tpl-<slug>-<unixnano>" (template_file_provider.go's
-- nextTemplateID), and team_id is actually populated from the issuing
-- principal's identifier (handlers_certificates.go's
-- authorizeCertificateMutationRequest), never a row in `teams` -- neither
-- value is ever a UUID. Both FKs independently reject every real issuance,
-- and the persist error was discarded (S-50), so certificates were never
-- durable; dropping the FK alone is also not enough, since a real,
-- non-UUID value left in a UUID-typed column would still fail with
-- SQLSTATE 22P02 (invalid input syntax for type uuid). ca_id is untouched:
-- certificate_authorities IS authoritative (CAs are only ever created
-- through the app, never file-backed).
-- Constraint names are Postgres's default auto-generated
-- <table>_<column>_fkey (000002_templates_ca_certs_core never names them
-- explicitly) -- confirmed against a disposable postgres:16-alpine
-- container before writing this.
-- Depends on: 000002
-- Rollback pair: 000042_certificates_drop_nonauthoritative_fks.down.sql

BEGIN;

ALTER TABLE certificates DROP CONSTRAINT IF EXISTS certificates_template_id_fkey;
ALTER TABLE certificates DROP CONSTRAINT IF EXISTS certificates_team_id_fkey;

ALTER TABLE certificates ALTER COLUMN template_id TYPE TEXT USING template_id::text;
ALTER TABLE certificates ALTER COLUMN team_id TYPE TEXT USING team_id::text;

COMMIT;
