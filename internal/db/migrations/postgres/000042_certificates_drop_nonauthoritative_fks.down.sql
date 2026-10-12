-- Wave S rollback (PostgreSQL)
-- Paired with: 000042_certificates_drop_nonauthoritative_fks.up.sql
--
-- Restores the original UUID typing and FKs. Narrowing TEXT back to UUID
-- must happen before the FK is re-added (a FK requires matching types with
-- the UUID-typed certificate_templates.id/teams.id it references), and both
-- steps reverse cleanly only against data whose template_id/team_id values
-- already satisfy them -- i.e. rolled back before a real, non-authoritative
-- (non-UUID) value has been written. A "tpl-*"-shaped or issuing-principal
-- string in either column at rollback time fails the ::uuid cast outright,
-- the same assumption every other down.sql in this tree makes about
-- reversing cleanly.

BEGIN;

ALTER TABLE certificates ALTER COLUMN template_id TYPE UUID USING template_id::uuid;
ALTER TABLE certificates ALTER COLUMN team_id TYPE UUID USING team_id::uuid;

ALTER TABLE certificates
    ADD CONSTRAINT certificates_template_id_fkey
    FOREIGN KEY (template_id) REFERENCES certificate_templates(id);

ALTER TABLE certificates
    ADD CONSTRAINT certificates_team_id_fkey
    FOREIGN KEY (team_id) REFERENCES teams(id);

COMMIT;
