-- W22-14 (PostgreSQL) — baseline issuance policy; semantics identical to sqlite.
-- Depends on: 000036
-- Rollback pair: 000088_issuance_policy_baseline.down.sql

BEGIN;

INSERT INTO issuance_policies (id, name, enabled, ca_id, rules, created_at, updated_at)
SELECT 'pol-baseline', 'Baseline', 1, '', '{"allowed_algorithms":["ECDSA-P256","ECDSA-P384","Ed25519","RSA-4096","ML-DSA-44","ML-DSA-65","ML-DSA-87","Hybrid-ECDSA-P256-ML-DSA-65","Hybrid-ECDSA-P384-ML-DSA-87"],"min_rsa_bits":3072,"max_validity_days":398,"allow_ca_certs":false}', to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
WHERE NOT EXISTS (SELECT 1 FROM issuance_policies);

COMMIT;
