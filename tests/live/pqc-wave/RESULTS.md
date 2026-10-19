# W31-11 live test: PQC wave against real TLS endpoints
date:    2026-10-17T00:14:07Z
commit:  89f7f1201f3ad87d8bc9ab3fc25006ad92bc589c (v0.15.0-28-g89f7f120)
db:      postgres
mode:    stop at first FAIL
machine: Darwin 27.0.0 arm64, go1.27.1, podman 6.1.3, OpenSSL 3.6.5
endpoint image: localhost/kkw31-11-ep:b3f8c1 (alpine:3.22, nginx + sshd)

=== 0. build endpoint image, check its OpenSSL ===
endpoint openssl: 3.5.9
PASS: endpoint image has OpenSSL 3.5.9 with ML-DSA-65
PASS: nginx links the system libssl

=== 1. build hub, Postgres, start hub ===

=== build hub (linux/arm64) and start Postgres ===
PASS: hub built from this checkout
PASS: postgres ready on network kkw31-11-net
PASS: hub up at https://localhost:18451
PASS: create template (ECDSA + ML-DSA-65) -> 201

=== 2. start 3 endpoints (ep-a, ep-b healthy; ep-fail is the would-be failing one) ===
PASS: all three endpoints serve TLS (placeholder ECDSA leaf)

=== 3. credentials, targets, install a hub-issued ECDSA leaf on each endpoint ===
PASS: [ep-a] create ssh credential -> 201
PASS: [ep-a] create target -> 201
PASS: [ep-a] issue ECDSA leaf -> 201
PASS: [ep-a] renewal/execute installs it over SSH -> 200
PASS: [ep-a] serves the hub-issued ECDSA leaf (serial 324C10ADB69C8EE9DC58B31E9B409117), the wave member
PASS: [ep-b] create ssh credential -> 201
PASS: [ep-b] create target -> 201
PASS: [ep-b] issue ECDSA leaf -> 201
PASS: [ep-b] renewal/execute installs it over SSH -> 200
PASS: [ep-b] serves the hub-issued ECDSA leaf (serial B5B62878B323F0CBEC4522DF6BDB07AA), the wave member
PASS: [ep-fail] create ssh credential -> 201
PASS: [ep-fail] create target -> 201
PASS: [ep-fail] issue ECDSA leaf -> 201
PASS: [ep-fail] renewal/execute installs it over SSH -> 200
PASS: [ep-fail] serves the hub-issued ECDSA leaf (serial E7FC5A62AF957F83B0DD8072A5141857), the wave member

=== 4. wave: create, add 3 bound members + 1 unbound, accept ===
PASS: issue the unbound member (no target names it) -> 201
PASS: create wave -> 201
PASS: add member 605f927ed57b -> 200
PASS: add member 62c5de38519d -> 200
PASS: add member ee99472b7d96 -> 200
PASS: add member 3e2333ecead7 -> 200
PASS: accept wave -> 200

=== 5. two-principal execute: alice proposes, alice may not approve, bob approves ===
PASS: alice proposes execute -> 201
PASS: alice cannot approve her own proposal -> 403
PASS: bob approves and the wave runs -> 200
execute result: {'migrated': 1, 'failed': 0, 'skipped': 0, 'unsupported': 3, 'regressed': False, 'wave_status': None}

=== 6. per-member outcomes as the real hub reported them ===
PASS: [ep-a] member status=delivery_unsupported delivery=unsupported
PASS: [ep-a] reason cites D-103: PQC key material cannot be installed yet (D-103 generate-without-deliver); manual install
PASS: [ep-a] successor 7250d87af0d9 was issued as ML-DSA-65 (hub inventory)
PASS: [ep-b] member status=delivery_unsupported delivery=unsupported
PASS: [ep-b] reason cites D-103: PQC key material cannot be installed yet (D-103 generate-without-deliver); manual install
PASS: [ep-b] successor 5d86227d6ec4 was issued as ML-DSA-65 (hub inventory)
PASS: [ep-fail] member status=delivery_unsupported delivery=unsupported
PASS: [ep-fail] reason cites D-103: PQC key material cannot be installed yet (D-103 generate-without-deliver); manual install
PASS: [ep-fail] successor 3d5978ef8ec8 was issued as ML-DSA-65 (hub inventory)
PASS: unbound member status=migrated delivery=none (no target, nothing to deliver)

=== 7. endpoints still serve the OLD certificate (no outage), observed by openssl s_client ===
PASS: [ep-a] served serial unchanged (324C10ADB69C8EE9DC58B31E9B409117): old cert still served
PASS: [ep-a] served certificate is not ML-DSA (as expected while delivery is unsupported)
PASS: [ep-b] served serial unchanged (B5B62878B323F0CBEC4522DF6BDB07AA): old cert still served
PASS: [ep-b] served certificate is not ML-DSA (as expected while delivery is unsupported)
PASS: [ep-fail] served serial unchanged (E7FC5A62AF957F83B0DD8072A5141857): old cert still served
PASS: [ep-fail] served certificate is not ML-DSA (as expected while delivery is unsupported)

=== 8. wave status and audit trail ===
wave: status migrated total leaf_only = in_progress 4 4 4
PASS: wave not reported done (status in_progress)
PASS: audit has pqc.wave_execute_approve
PASS: audit has pqc.wave_execute_propose
PASS: audit has 4 pqc.wave_member_result rows (one per member)

=== 9. legs this harness cannot honestly run yet ===
PENDING: [ep-a] served serial changes to the ML-DSA cert -- blocked on the ML-DSA private-key export follow-up (production deliverer is unsupportedWaveDeliverer, D-103)
PENDING: [ep-b] served serial changes to the ML-DSA cert -- same blocker
PENDING: [ep-fail] injected verify failure is rolled back and the old serial is still served -- same blocker (no Deliver is ever attempted, so there is nothing to roll back)

=== 10. summary ===
ALL RUN STEPS PASSED (3 legs PENDING, nothing claimed for them)
