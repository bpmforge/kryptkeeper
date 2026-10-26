# W31-11 live test: PQC wave against real TLS endpoints
date:    2026-10-19T16:45:13Z
commit:  5d041b04ee41cc0f019bf87f06180a391a08bd37 (v1.0.0-1-g5d041b04)
db:      postgres
mode:    keep-going (runs every step after a FAIL)
machine: Darwin 27.0.0 arm64, go1.27.1, podman 6.1.3, OpenSSL 3.6.5
endpoint image: localhost/kkw31-11-ep:eba7f6 (alpine:3.22, nginx + sshd)

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
PASS: all three endpoints serve TLS (placeholder ECDSA leaf) and sshd listens

=== 3. credentials, targets, install a hub-issued ECDSA leaf on each endpoint ===
PASS: [ep-a] create ssh credential -> 201
PASS: [ep-a] create target -> 201
PASS: [ep-a] issue ECDSA leaf -> 201
PASS: [ep-a] renewal/execute installs it over SSH -> 200
PASS: [ep-a] serves the hub-issued ECDSA leaf (serial 26F45E1F97CA6E4EA42A1E3574826C16), the wave member
PASS: [ep-b] create ssh credential -> 201
PASS: [ep-b] create target -> 201
PASS: [ep-b] issue ECDSA leaf -> 201
PASS: [ep-b] renewal/execute installs it over SSH -> 200
PASS: [ep-b] serves the hub-issued ECDSA leaf (serial 5BAE6A20CC2589B6EE90AB195111EC04), the wave member
PASS: [ep-fail] create ssh credential -> 201
PASS: [ep-fail] create target -> 201
PASS: [ep-fail] issue ECDSA leaf -> 201
PASS: [ep-fail] renewal/execute installs it over SSH -> 200
PASS: [ep-fail] serves the hub-issued ECDSA leaf (serial 9061E00764BF85DB2D7AEED6E6C73975), the wave member

=== 4. wave: create, add 3 bound members + 1 unbound, accept ===
PASS: issue the unbound member (no target names it) -> 201
PASS: create wave -> 201
PASS: add member 038708a18a50 -> 200
PASS: add member 83f0d777b241 -> 200
PASS: add member eae9114afbed -> 200
PASS: add member a172b2e72218 -> 200
PASS: accept wave -> 200

=== 4b. inject the failure: ep-fail's verify address points at ep-a (wrong fingerprint after install) ===
PASS: [ep-fail] PATCH verify_host_port -> ep-a:443 -> 200

=== 5. two-principal execute: alice proposes, alice may not approve, bob approves ===
PASS: alice proposes execute -> 201
PASS: alice cannot approve her own proposal -> 403
PASS: bob approves and the wave runs -> 200
execute result: {'migrated': 3, 'failed': 1, 'skipped': 0, 'unsupported': 0, 'regressed': True, 'wave_status': 'regressed'}

=== 6. per-member outcomes as the real hub reported them ===
PASS: [ep-a] member status=migrated delivery=verified
PASS: [ep-a] successor b5a0d1bfb8ad was issued as ML-DSA-65 (hub inventory)
PASS: [ep-b] member status=migrated delivery=verified
PASS: [ep-b] successor eb4a34df551a was issued as ML-DSA-65 (hub inventory)
PASS: [ep-fail] member status=failed delivery=failed old_serial_served=true
PASS: [ep-fail] reason reports the rollback: delivery rolled_back: verify_failed: served fingerprint does not match renewed cert; rolled back
PASS: [ep-fail] successor da297fa17b77 was issued as ML-DSA-65 (hub inventory)
PASS: unbound member status=migrated delivery=none (no target, nothing to deliver)

=== 7. what the endpoints actually serve, observed by openssl s_client (not the hub) ===
PASS: [ep-a] serial changed 26F45E1F97CA6E4EA42A1E3574826C16 -> B3439CCA9376D974C0185E54EF4E5466 (the successor's serial)
PASS: [ep-a] served certificate is ML-DSA-65
PASS: [ep-b] serial changed 5BAE6A20CC2589B6EE90AB195111EC04 -> EBA952737B17A73F588FB7A14AB29529 (the successor's serial)
PASS: [ep-b] served certificate is ML-DSA-65
PASS: [ep-fail] rolled back: old serial 9061E00764BF85DB2D7AEED6E6C73975 still served
PASS: [ep-fail] served certificate is still the ECDSA leaf
PASS: [ep-fail] private key file restored byte-for-byte

=== 8. wave status and audit trail ===
wave: status migrated total leaf_only = regressed 3 4 4
PASS: wave reported regressed (not done)
PASS: audit has pqc.wave_execute_approve
PASS: audit has pqc.wave_execute_propose
PASS: audit has 4 pqc.wave_member_result rows (one per member)
PASS: audit has 3 key.export_for_delivery rows (one per exported successor key)
PASS: audit trail contains no private-key PEM

=== 9. summary ===
ALL PASS
