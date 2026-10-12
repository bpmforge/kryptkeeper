-- Rollback of 000069 (SQLite). DROP COLUMN needs SQLite 3.35+, which the
-- bundled modernc.org/sqlite provides.

ALTER TABLE delivery_plugin_versions DROP COLUMN signer_key_id;
ALTER TABLE delivery_plugin_versions DROP COLUMN signature;
