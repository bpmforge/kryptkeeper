-- Wave W12 (SQLite) - rollback
-- SQLite does not support DROP COLUMN before v3.35. Recreate without ownership columns.

BEGIN;

CREATE TABLE certificates_rollback AS
SELECT
    fingerprint_sha256, serial_number, subject_dn, common_name, subject_alt_names,
    issuer_dn, issuer_cn, ca_id, template_id, team_id,
    valid_from, valid_until, public_key_algorithm, key_size_bits,
    signature_algorithm, extended_key_usage, key_usage,
    chain_complete, chain_trusted, pqc_vulnerable,
    risk_score, risk_flags, grade, renewal_method, renewal_status,
    source, raw_cert_b64, created_at, updated_at
FROM certificates;

DROP TABLE certificates;

ALTER TABLE certificates_rollback RENAME TO certificates;

COMMIT;
