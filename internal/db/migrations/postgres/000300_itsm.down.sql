-- Rollback of 000300_itsm.up.sql (events first: they reference connections).
DROP TABLE IF EXISTS itsm_events;
DROP TABLE IF EXISTS itsm_connections;
