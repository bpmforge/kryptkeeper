-- Rollback of 000383_certificate_cloud_resources.up.sql
BEGIN;

DROP TABLE IF EXISTS certificate_cloud_resources;

COMMIT;
