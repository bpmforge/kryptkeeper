# W31-04 live test: OpenSSL interop for ML-DSA and hybrid leaves
date:    2026-10-17T00:02:41Z
commit:  9eb9725abf9ab5a9256993b98d2f4e0c2615af06 (v0.15.0-21-g9eb9725a)
db:      postgres
mode:    stop at first FAIL
machine: Darwin 27.0.0 arm64, go1.27.1, podman 6.1.3, OpenSSL 3.6.5
verifier: OpenSSL 3.6.5 29 Sep 2026 (Library: OpenSSL 3.6.5 29 Sep 2026)

=== 0. OpenSSL version gate ===
PASS: openssl 3.6.5 >= 3.5

=== build hub (linux/arm64) and start Postgres ===
PASS: hub built from this checkout
PASS: postgres ready on network kkw31-04-net

=== 1. start hub with the bootstrap ECDSA root R ===
PASS: hub up at https://localhost:18441

=== 2. create ML-DSA-65 intermediate M and ECDSA-P256 intermediate C under R ===
PASS: create CA pqc-issuing-M (ML-DSA-65) -> 201
PASS: create CA pqc-issuing-C (ECDSA-P256) -> 201
PASS: M is an ML-DSA-65 certificate (openssl parses it)

=== 3. templates ===
PASS: create template tpl-pqc -> 201
PASS: create template tpl-ecdsa-only -> 201

=== 4. ML-DSA-44/65/87 leaves under classical C and under ML-DSA M ===
PASS: issue ML-DSA-44 leaf under C -> 201
PASS: ML-DSA-44 leaf, chain R,C: openssl verify OK
PASS: issue ML-DSA-44 leaf under M -> 201
PASS: ML-DSA-44 leaf, chain R,M (ML-DSA signature hop): openssl verify OK
PASS: issue ML-DSA-65 leaf under C -> 201
PASS: ML-DSA-65 leaf, chain R,C: openssl verify OK
PASS: issue ML-DSA-65 leaf under M -> 201
PASS: ML-DSA-65 leaf, chain R,M (ML-DSA signature hop): openssl verify OK
PASS: issue ML-DSA-87 leaf under C -> 201
PASS: ML-DSA-87 leaf, chain R,C: openssl verify OK
PASS: issue ML-DSA-87 leaf under M -> 201
PASS: ML-DSA-87 leaf, chain R,M (ML-DSA signature hop): openssl verify OK

=== 5. hybrid leaves under C (classical path only, D-104) ===
PASS: issue Hybrid-ECDSA-P256-ML-DSA-65 leaf under C -> 201
PASS: Hybrid-ECDSA-P256-ML-DSA-65 leaf, chain R,C (classical path): openssl verify OK
PASS: Hybrid-ECDSA-P256-ML-DSA-65 leaf parses and carries subjectAltPublicKeyInfo (2.5.29.72)
PASS: issue Hybrid-ECDSA-P384-ML-DSA-87 leaf under C -> 201
PASS: Hybrid-ECDSA-P384-ML-DSA-87 leaf, chain R,C (classical path): openssl verify OK
PASS: Hybrid-ECDSA-P384-ML-DSA-87 leaf parses and carries subjectAltPublicKeyInfo (2.5.29.72)
note: hybrid leaves are checked on the classical ECDSA path only; no LAMPS composite interop is claimed

=== 6. negative: allow-list refusal ===
PASS: ML-DSA-65 CSR with tpl-ecdsa-only refused: HTTP 422 (spec expects 422 policy_violation)

=== 7. negative: bad proof of possession ===
PASS: bad-PoP ML-DSA-65 CSR rejected -> 400
PASS: bad-PoP hybrid CSR rejected -> 400

=== 8. CRL and OCSP signed by the ML-DSA CA M, verified by openssl ===
PASS: openssl ocsp -issuer M -cert ML-DSA-65 leaf -> good (response verified)
PASS: revoke the M-issued ML-DSA-65 leaf -> 200
PASS: openssl ocsp -> revoked for the M leaf (ML-DSA-signed response verified by openssl)
PASS: M's CRL lists the revoked leaf serial
PASS: openssl verifies M's ML-DSA CRL signature against M

=== 9. summary ===

ALL STEPS PASSED
