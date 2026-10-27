<!-- Live record for gap P13, produced by tests/live/pqc-wave/run-apache-k8s.sh (a rerun overwrites this file; keep the prose above "Run record" elsewhere before rerunning). -->
# Live results: PQC wave delivery to Apache httpd, and Kubernetes Secret rollback (gap P13, 2026-10-26)

Scope and honesty notes:

- Run on the lead's shared Mac with podman 6.1.3 and kind 0.33 (podman provider), against `origin/main` at v1.1.0
  (66b2f9c0) plus only the new harness files; no product code changed. The run below is the third; runs one and two
  failed on a harness assertion of mine (see "Findings"), not on the product.
- Apache: alpine 3.22 `apache2` 2.4.69 with `mod_ssl`, linked to the system OpenSSL 3.5.9. The container has no
  systemd and no `apachectl`, so `systemctl reload apache2` is a shim for `httpd -k graceful` and `apachectl configtest`
  is a shim for `httpd -t`. The installer runs those two commands on a real host, so the shims stand in for the
  distribution scripts, not for any Kryptkeeper logic. Debian/RHEL packaging of httpd was not tested.
- Result: Apache httpd 2.4.69 on OpenSSL 3.5.9 loads and serves an ML-DSA-65 certificate and key delivered over SSH
  (`httpd -t` accepts it, `openssl s_client` reads ML-DSA-65 from the served leaf). No refusal occurred.
- Apache rollback: forced by pointing the target's `verify_host_port` at another Apache endpoint (wrong fingerprint).
  The install is verified by the hub's TLS dial, fails, and the previous certificate and key files are restored.
- Kubernetes rollback: kind with an OpenSSL 3.5.9 `s_server` workload reading the Secret volume (a stand-in for an
  ingress, not ingress-nginx). The failure is forced the same way: the target's `verify_host_port` points at the Apache
  endpoint, so the hub can never see the new leaf. The hub waits the full ~135s verify window, then PUTs the previous
  Secret manifest back.
- Not proved: a verify failure caused by a real product fault (for example a workload that cannot parse an ML-DSA key);
  Secret rollback on a cluster where the kubelet is slow beyond the observed lag; Apache from Debian/RHEL packages;
  mod_md or a front proxy in front of httpd; Tomcat, Windows, F5, Citrix (still refused, unit-tested).

Findings:

- Kubelet lag is visible. After the wave the probe saw the previous serial, then the unverified ML-DSA successor, then the
  previous serial again (sequence in the record). The hub's verify never saw the successor (it dials the misdirected
  address), but the pod itself picked it up from the Secret volume before the rollback propagated. So during a k8s
  rollback the workload can serve the unverified certificate for up to a kubelet sync period. The first two runs
  asserted "serves the previous serial" and "is not ML-DSA" back to back, saw the transient, and failed; the harness now
  waits for four consecutive samples of the previous serial before asserting. This is a property of Secret volumes, not
  a rollback defect: the Secret bytes are byte-identical to before the wave.

## Run record

# PQC wave delivery to Apache httpd, and Kubernetes Secret rollback after a failed verify
date:    2026-10-26T14:41:00Z
commit:  66b2f9c002fab8c30f125a9cd2232acee0347cd6 (v1.1.0)
db:      postgres
mode:    keep-going (runs every step after a FAIL)
machine: Darwin 27.0.0 arm64, go1.27.1, podman 6.1.3, OpenSSL 3.6.5

=== 0. build endpoint image, check Apache httpd and OpenSSL ===
endpoint openssl: 3.5.9
httpd: Server version: Apache/2.4.69 (Unix)
 ssl_module (shared)
PASS: httpd has mod_ssl, linked to the image's system OpenSSL 3.5.9

=== 1. build hub, Postgres, start hub ===

=== build hub (linux/arm64) and start Postgres ===
PASS: hub built from this checkout
PASS: postgres ready on network kkak8s-net
PASS: hub up at https://localhost:18462
PASS: create template (ECDSA + ML-DSA-65) -> 201

=== 2. start 2 apache endpoints ===
PASS: both apache endpoints serve TLS (placeholder ECDSA leaf) and sshd listens

=== 3. apache: credentials, targets, install a hub-issued ECDSA leaf ===
PASS: [ep-a] create ssh credential -> 201
PASS: [ep-a] create apache target (cert + key paths) -> 201
PASS: [a] issue ECDSA leaf -> 201
PASS: [ep-a] renewal/execute installs it over SSH -> 200
PASS: [ep-a] apache serves the hub-issued ECDSA leaf (serial A768086FC1474ADA491688852C8D6DC), the wave member
PASS: [ep-af] create ssh credential -> 201
PASS: [ep-af] create apache target (cert + key paths) -> 201
PASS: [af] issue ECDSA leaf -> 201
PASS: [ep-af] renewal/execute installs it over SSH -> 200
PASS: [ep-af] apache serves the hub-issued ECDSA leaf (serial 8E8F69E34597360EB9B9A968A7B40CC2), the wave member

=== 4. kind cluster, OpenSSL 3.5 workload on a TLS Secret, k8s target ===
PASS: kind cluster kkak8s-ce9eb4 up (podman provider, API on 192.0.2.166)
PASS: workload image loaded into kind
PASS: namespace + placeholder TLS Secret created
PASS: workload pod ready
PASS: [k8s] create api_token credential -> 201
PASS: [k8s] create target -> 201
PASS: [k] issue ECDSA leaf -> 201
PASS: [k8s] renewal/execute pushes the ECDSA leaf into the Secret -> 200
PASS: [k8s] the workload serves the hub-issued ECDSA leaf (serial 49EF02A7DB0EE7625305F5523FDF6F28)

=== 5. wave: create, add members, accept ===
PASS: create wave -> 201
PASS: add member [a] -> 200
PASS: add member [af] -> 200
PASS: add member [k] -> 200
PASS: accept wave -> 200
PASS: [k8s] PATCH verify_host_port -> ep-a:443 (serves a different cert, so verify can never match) -> 200
PASS: [ep-af] PATCH verify_host_port -> ep-a:443 (wrong fingerprint after install) -> 200

=== 6. two-principal execute ===
PASS: alice proposes execute -> 201
PASS: alice cannot approve her own proposal -> 403
PASS: bob approves and the wave runs -> 200
execute result: {'migrated': 1, 'failed': 2, 'skipped': 0, 'unsupported': 0, 'regressed': True, 'wave_status': 'regressed'}

=== 7. per-member outcomes as the hub reported them ===
PASS: [a] status=migrated delivery=verified
PASS: [a] successor a1a92da95d99 is ML-DSA-65 in the hub inventory
PASS: [af] status=failed delivery=failed old_serial_served=true
PASS: [af] reason reports the rollback: delivery rolled_back: verify_failed: served fingerprint does not match renewed cert; rolled back
PASS: [af] successor 03a406c9a246 is ML-DSA-65 in the hub inventory
PASS: [k] status=failed delivery=failed old_serial_served=true
PASS: [k] reason reports the rollback: delivery rolled_back: verify_failed: served fingerprint does not match renewed cert; rolled back
PASS: [k] successor 5f7a0a02ae6c is ML-DSA-65 in the hub inventory

=== 8. what the endpoints actually serve, observed by openssl s_client in a container ===
PASS: [ep-a] apache serial A768086FC1474ADA491688852C8D6DC -> 64392159802DFD6FC21814DBA2F307BA (the successor)
PASS: [ep-a] served certificate is ML-DSA-65
PASS: [ep-a] httpd -t accepts the delivered ML-DSA cert and key
PASS: [ep-af] rolled back: old serial 8E8F69E34597360EB9B9A968A7B40CC2 still served
PASS: [ep-af] cert and key files restored byte-for-byte
[k8s] serials seen by the probe after the wave (in order): 49EF02A7DB0EE7625305F5523FDF6F28 155050286FBBD0F351C38C4EAD30A6CE 49EF02A7DB0EE7625305F5523FDF6F28
PASS: [k8s] rolled back: workload stably serves the previous serial 49EF02A7DB0EE7625305F5523FDF6F28 again
PASS: [k8s] workload serves a non-ML-DSA certificate after rollback ( Public Key Algorithm: id-ecPublicKey)
PASS: [k8s] Secret tls.crt and tls.key restored byte-for-byte

=== 9. wave status and audit trail ===
wave: status migrated total = regressed 1 3
PASS: wave reported regressed (ep-af failed)
PASS: audit has 3 key.export_for_delivery rows (>= 3 members)
PASS: audit trail contains no private-key PEM

=== 10. summary ===
ALL PASS
