BEGIN;
UPDATE issuance_policies SET rules = '{"allowed_algorithms":["ECDSA-P256","ECDSA-P384","Ed25519","RSA-4096","ML-DSA-44","ML-DSA-65","ML-DSA-87","Hybrid-ECDSA-P256-ML-DSA-65","Hybrid-ECDSA-P384-ML-DSA-87"],"min_rsa_bits":3072,"max_validity_days":398,"allow_ca_certs":false}'
WHERE id = 'pol-baseline' AND rules = '{"allowed_algorithms":["ECDSA-P256","ECDSA-P384","Ed25519","RSA-3072","RSA-4096","ML-DSA-44","ML-DSA-65","ML-DSA-87","Hybrid-ECDSA-P256-ML-DSA-65","Hybrid-ECDSA-P384-ML-DSA-87"],"min_rsa_bits":3072,"max_validity_days":398,"allow_ca_certs":false}';

COMMIT;
