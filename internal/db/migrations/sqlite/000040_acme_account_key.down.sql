-- Deliberately asymmetric with up.sql: up.sql's CREATE TABLE IF NOT EXISTS
-- only ever creates acme_accounts on a fresh database (see its comment); in
-- every real deployment the table predates this migration and holds live
-- account data, so rolling back drops only the jwk column it added, never
-- the table itself.
ALTER TABLE acme_accounts DROP COLUMN jwk;
