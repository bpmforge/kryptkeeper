-- Rollback of 000070 (SQLite). DROP COLUMN needs SQLite 3.35+, which the
-- bundled modernc.org/sqlite provides.

ALTER TABLE ssh_certificates DROP COLUMN template_id;
