# W23-37 live test: revoke an issuing CA, OCSP on a child leaf, CRL check
date:    2026-10-16T02:47:35Z
commit:  883962e07dfcd20afd52672adcc10ef96434d362 (internal/v2.2.0-1687-g883962e0)
db:      postgres
mode:    stop at first FAIL
machine: Darwin 27.0.0 arm64, go1.27.1, podman 6.1.3, OpenSSL 3.6.5

=== build hub (linux/arm64) and start Postgres ===
PASS: hub built from this checkout
PASS: postgres ready on network kkw23rev-net

=== start hub with the bootstrap root R ===
PASS: hub up at https://localhost:18437 (admins alice and bob from APP_API_KEYS_JSON)
PASS: create intermediate I (RSA-2048, so SCEP can use it) under R -> 201
PASS: I chain split: first cert is I, second is R
PASS: issue leaf L from I -> 201

=== 3. baseline: OCSP for L is good ===
PASS: openssl ocsp -issuer I -cert L -> good

=== step 5a. restart hub so ACME/EST/CMP issue from I and SCEP uses I ===
PASS: SCEP enabled on I
PASS: CMP enabled
PASS: minted two one-time SCEP challenges (before the revoke)

=== 4. enrolment baseline through I on ACME, EST, SCEP, CMP ===
PASS: ACME (lego) issued a cert that chains to I
PASS: EST (globalsign/est) enrolled
PASS: SCEP (micromdm/scep) enrolled
PASS: CMP (openssl cmp ir) enrolled

=== 5. blast radius, then A proposes the revoke (I must stay active) ===
PASS: GET blast-radius retire_ca target=I -> 200
PASS: blast radius reports 11 affected (>= 1)
PASS: A POST /cas/I/revoke is only proposed -> 202
PASS: GET /cas/I -> 200
PASS: I is still active while the revoke is pending
PASS: L still good while pending

=== 6. dual control ===
PASS: A approving own revoke -> 403
PASS: B approves -> 200
PASS: GET /cas/I -> 200
PASS: I status=revoked

=== 7. OCSP for L within 60 s, parent CRL lists I ===
PASS: openssl ocsp for child leaf L reports revoked after 0 s (budget 60 s)
PASS: parent CRL (R) signature verifies against R
PASS: parent CRL lists I's serial (EBDB3521E0476DC1F23D1831BD30C7E6)
PASS: the entry carries reason CA Compromise
info: I's own CRL does not list leaf L: a CRL-only relying party learns of the revoke from the parent CRL (R) listing I, as the ticket requires; OCSP answers revoked for L directly

=== 8. enrolment through revoked I fails on all four protocols ===
PASS: ACME refused: issuing CA revoked
PASS: EST refused at enroll: FAIL enroll: issuing CA revoked
PASS: SCEP refused (unused one-time challenge minted before the revoke)
PASS: CMP refused: CMP info: received ERROR
hub log: 2026/10/16 02:53:41 acme finalize issuance failed: ca is revoked: ca is not active: 9baa8403-d6c7-48d0-b0ea-3424d2d4620a
hub log: 2026/10/16 02:53:49 est est.enroll: issuance failed: ca is revoked: ca is not active: 9baa8403-d6c7-48d0-b0ea-3424d2d4620a
hub log: 2026/10/16 02:53:55 scep PKIOperation: issuance failed: ca is revoked: ca is not active: 9baa8403-d6c7-48d0-b0ea-3424d2d4620a
hub log: 2026/10/16 02:53:56 cmp: issuance failed: ca is revoked: ca is not active: 9baa8403-d6c7-48d0-b0ea-3424d2d4620a

=== 9. summary ===

| Check | Result |
|---|---|
| baseline ACME / EST / SCEP / CMP enrol through I | PASS / PASS / PASS / PASS |
| A proposes revoke: 202, I stays active; A cannot self-approve (403); B approves | see PASS lines above |
| OCSP for child leaf L: revoked | see step 7 |
| parent CRL lists I with CA Compromise | see step 7 |
| ACME, EST, SCEP, CMP refused after revoke | see step 8 |

ALL STEPS PASSED
