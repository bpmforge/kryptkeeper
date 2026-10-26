<!-- Live record for W40-01 / D-315, produced by tests/live/pqc-wave/run-w40.sh (a rerun overwrites this file). -->
# Live results: PQC wave delivery to HAProxy and Kubernetes (W40-01, 2026-10-25)

Scope and honesty notes:

- Run on the lead's shared Mac with podman 6.1.3 and kind (podman provider), against the working tree of branch
  `worktree-agent-a623998aeb3696a62` (base a91c4f29 plus the W40-01 changes, uncommitted when run).
- HAProxy: alpine 3.22 haproxy 3.2.26 running on OpenSSL 3.5.9. The container has no systemd, so
  `systemctl reload haproxy` is a shim that sends SIGUSR2 to the master (what the stock unit's ExecReload does).
  HAProxy documents no ML-DSA certificate support; this run is the evidence that `haproxy -c` accepts and the
  workers serve an ML-DSA-65 certificate on that build. A build that cannot load the key fails `haproxy -c`
  and the install rolls back (unit-tested).
- Kubernetes: kind with an OpenSSL 3.5.9 `s_server` workload reading the Secret volume (it re-reads the files per
  connection). It stands in for an ingress built on OpenSSL 3.5; it is not ingress-nginx itself.
- Not run live: Secret rollback after a failed k8s verify (the verify window is ~135s; covered by
  `internal/agentinstall` k8s tests), Tomcat, Windows, F5, Citrix (refused with reasons, unit-tested).
- The first two attempts failed on a harness defect (default ServiceAccount race) and on a product defect: the
  wave approve connection was cut by the 15s server write timeout while the k8s verify waited, so the response was
  lost. Fixed in `handleWaveExecuteApprove`; the run below is the third.

## Run record

# W40-01 live test: PQC wave delivery to haproxy and a Kubernetes TLS Secret
date:    2026-10-25T16:33:06Z
commit:  a91c4f290936b5b582a050e099dc8aaaba3c4afb (v1.0.0-86-ga91c4f29)
db:      postgres
mode:    keep-going (runs every step after a FAIL)
machine: Darwin 27.0.0 arm64, go1.27.1, podman 6.1.3, OpenSSL 3.6.5

=== 0. build endpoint image, check haproxy and OpenSSL ===
endpoint openssl: 3.5.9
haproxy: HAProxy version 3.2.26-3e0f11a 2026/10/14 - https://haproxy.org/
Built with SSL library version : OpenSSL 3.5.9 29 Sep 2026
Running on SSL library version : OpenSSL 3.5.9 29 Sep 2026
PASS: haproxy runs on OpenSSL 3.5.9

=== 1. build hub, Postgres, start hub ===

=== build hub (linux/arm64) and start Postgres ===
PASS: hub built from this checkout
PASS: postgres ready on network kkw40-net
PASS: hub up at https://localhost:18452
PASS: create template (ECDSA + ML-DSA-65) -> 201

=== 2. start 2 haproxy endpoints ===
PASS: both haproxy endpoints serve TLS (placeholder ECDSA leaf) and sshd listens

=== 3. haproxy: credentials, targets, install a hub-issued ECDSA leaf ===
PASS: [ep-h] create ssh credential -> 201
PASS: [ep-h] create haproxy target (combined PEM, no key path) -> 201
PASS: [h] issue ECDSA leaf -> 201
PASS: [ep-h] renewal/execute installs it over SSH -> 200
PASS: [ep-h] haproxy serves the hub-issued ECDSA leaf (serial BD6755ED3BB528EAA3D346DE794BA5D4), the wave member
PASS: [ep-hf] create ssh credential -> 201
PASS: [ep-hf] create haproxy target (combined PEM, no key path) -> 201
PASS: [hf] issue ECDSA leaf -> 201
PASS: [ep-hf] renewal/execute installs it over SSH -> 200
PASS: [ep-hf] haproxy serves the hub-issued ECDSA leaf (serial 3E006CE8824A9575A39D44A38EC6757E), the wave member

=== 4. kind cluster, OpenSSL 3.5 workload on a TLS Secret, k8s target ===
PASS: kind cluster kkw40-d47a19 up (podman provider, API on 192.0.2.166)
PASS: workload image loaded into kind
PASS: namespace + placeholder TLS Secret created
PASS: workload pod ready
PASS: [k8s] create api_token credential -> 201
PASS: [k8s] create target -> 201
PASS: [k] issue ECDSA leaf -> 201
PASS: [k8s] renewal/execute pushes the ECDSA leaf into the Secret -> 200
PASS: [k8s] the workload serves the hub-issued ECDSA leaf (serial B6014D4BC0B411F01337545CA7A23AC4)

=== 5. wave: create, add members, accept ===
PASS: create wave -> 201
PASS: add member [h] -> 200
PASS: add member [hf] -> 200
PASS: add member [k] -> 200
PASS: accept wave -> 200
PASS: [ep-hf] PATCH verify_host_port -> ep-h:443 (wrong fingerprint after install) -> 200

=== 6. two-principal execute ===
PASS: alice proposes execute -> 201
PASS: alice cannot approve her own proposal -> 403
PASS: bob approves and the wave runs -> 200
execute result: {'migrated': 2, 'failed': 1, 'skipped': 0, 'unsupported': 0, 'regressed': True, 'wave_status': 'regressed'}

=== 7. per-member outcomes as the hub reported them ===
PASS: [h] status=migrated delivery=verified
PASS: [h] successor a27226066252 is ML-DSA-65 in the hub inventory
PASS: [ep-hf] status=failed delivery=failed old_serial_served=true
PASS: [ep-hf] reason reports the rollback: delivery rolled_back: verify_failed: served fingerprint does not match renewed cert; rolled back
PASS: [hf] successor 5106c81b424d is ML-DSA-65 in the hub inventory
PASS: [k] status=migrated delivery=verified
PASS: [k] successor 9f516839a9e0 is ML-DSA-65 in the hub inventory

=== 8. what the endpoints actually serve, observed by openssl s_client in a container ===
PASS: [ep-h] haproxy serial BD6755ED3BB528EAA3D346DE794BA5D4 -> 31FC212FCA074286149265901AD0C80 (the successor)
PASS: [ep-h] served certificate is ML-DSA-65
PASS: [ep-h] haproxy -c accepts the delivered combined PEM
PASS: [ep-hf] rolled back: old serial 3E006CE8824A9575A39D44A38EC6757E still served
PASS: [ep-hf] combined PEM restored byte-for-byte
PASS: [k8s] workload serial B6014D4BC0B411F01337545CA7A23AC4 -> CED104EFBBA1ACE13D0709C296F69880 (the successor)
PASS: [k8s] served certificate is ML-DSA-65
PASS: [k8s] Secret tls.key is a PKCS#8 PRIVATE KEY PEM

=== 9. wave status and audit trail ===
wave: status migrated total = regressed 2 3
PASS: wave reported regressed (ep-hf failed)
PASS: audit has 3 key.export_for_delivery rows (>= 3 members)
PASS: audit trail contains no private-key PEM

=== 10. summary ===
ALL PASS
