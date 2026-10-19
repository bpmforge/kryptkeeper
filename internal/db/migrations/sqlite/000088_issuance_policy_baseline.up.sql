-- W22-14 (FR-P8): baseline issuance policy. Inserted only when the table is
-- empty (fresh installs AND upgraded installs that never defined a policy):
-- RSA >= 3072, validity <= 398 days, no CA certs through the leaf path.
-- An operator who already manages policies is never overridden.
INSERT INTO issuance_policies (id, name, enabled, ca_id, rules, created_at, updated_at)
SELECT 'pol-baseline', 'Baseline', 1, '', '{"allowed_algorithms":["ECDSA-P256","ECDSA-P384","Ed25519","RSA-4096","ML-DSA-44","ML-DSA-65","ML-DSA-87","Hybrid-ECDSA-P256-ML-DSA-65","Hybrid-ECDSA-P384-ML-DSA-87"],"min_rsa_bits":3072,"max_validity_days":398,"allow_ca_certs":false}', strftime('%Y-%m-%dT%H:%M:%SZ','now'), strftime('%Y-%m-%dT%H:%M:%SZ','now')
WHERE NOT EXISTS (SELECT 1 FROM issuance_policies);
