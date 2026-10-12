BEGIN;

DROP TABLE IF EXISTS connectors;
ALTER TABLE certificates DROP COLUMN renewal_connector_id;

COMMIT;
