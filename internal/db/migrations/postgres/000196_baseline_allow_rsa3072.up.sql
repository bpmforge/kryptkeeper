BEGIN;
-- W26 UAT finding: the W22-14 Baseline states RSA >= 3072 (min_rsa_bits 3072)
-- but its allow-list named only RSA-4096, so RSA-3072 keys were refused by
-- allowed_algorithms. Add RSA-3072. Only a Baseline row still holding the
-- exact seeded rules is touched; an operator-edited policy is left alone.
UPDATE issuance_policies SET rules = '{"allowed_algorithms":["ECDSA-P256","ECDSA-P384","Ed25519","RSA-3072","RSA-4096","ML-DSA-44","ML-DSA-65","ML-DSA-87","Hybrid-ECDSA-P256-ML-DSA-65","Hybrid-ECDSA-P384-ML-DSA-87"],"min_rsa_bits":3072,"max_validity_days":398,"allow_ca_certs":false}', updated_at = to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
WHERE id = 'pol-baseline' AND rules = '{"allowed_algorithms":["ECDSA-P256","ECDSA-P384","Ed25519","RSA-4096","ML-DSA-44","ML-DSA-65","ML-DSA-87","Hybrid-ECDSA-P256-ML-DSA-65","Hybrid-ECDSA-P384-ML-DSA-87"],"min_rsa_bits":3072,"max_validity_days":398,"allow_ca_certs":false}';

COMMIT;
