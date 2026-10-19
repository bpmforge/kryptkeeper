-- W23-19: the CA certificate a rotation retired, so OCSP can keep answering for
-- leaves issued under it while the retired key still exists. Empty on rows
-- written before this migration (those rotations cannot be answered for).
-- Depends on: 000027 (ca_key_rotations)
-- Rollback pair: 000129_ca_key_rotations_old_cert.down.sql

ALTER TABLE ca_key_rotations ADD COLUMN old_cert_pem TEXT NOT NULL DEFAULT '';
