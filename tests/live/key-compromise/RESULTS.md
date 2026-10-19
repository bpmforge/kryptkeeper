# W23-41 live key-compromise drill
date:    2026-10-16T02:54:05Z
commit:  883962e07dfcd20afd52672adcc10ef96434d362 (internal/v2.2.0-1687-g883962e0)
db:      postgres
mode:    stop at first FAIL
machine: Darwin 27.0.0 arm64, go1.27.1, podman 6.1.3, OpenSSL 3.6.5

=== build hub (linux/arm64) and start Postgres ===
PASS: hub built from this checkout
PASS: postgres ready on network kkw23cmp-net

=== managed target: sshd + nginx container (image from tests/live/ssh-install, key injected at run time) ===
PASS: reusing cached localhost/kkw23cmp-ssh:latest
PASS: sshd and nginx up; host key captured for pinning

=== start hub with alice, bob, carol (all pki-admin) ===
PASS: hub up at https://localhost:18438
PASS: ssh_key credential stored
PASS: managed target for L1 (kkw23cmp-ssh, reachable) -> 201
PASS: managed target for L3 (kkw23cmp-down, no such host) -> 201

=== 1. CA C with key K and leaves L1, L2, L3 ===
PASS: create CA C -> 201
PASS: GET /cas/C -> 200
PASS: GET /keys/K (K = key-<C id>; the CA API exposes no key_id) -> 200
PASS: issue L1 (CN kkw23cmp-ssh, matches the reachable target) -> 201
PASS: issue L2 (no managed target) -> 201
PASS: issue L3 (CN kkw23cmp-down, matches the unreachable target) -> 201

=== 2. key policy and ACL ===
PASS: PUT /keys/K/policy -> 200
PASS: third admin (carol, not on the ACL) POST /keys/K/rotate -> 403

=== 3. baseline OCSP for L1..L3 (issuer = C's pre-rotation certificate) ===
PASS: L1 -> good
PASS: L2 -> good
PASS: L3 -> good

=== 4. A proposes the compromise; nothing may change before approval ===
PASS: A POST /keys/K/compromise -> 202
PASS: GET /keys/K/policy -> 200
PASS: no compromised_at before approval
PASS: key metadata unchanged (K not rotated)

=== 5. dual control ===
PASS: A approving own action -> 403
PASS: B approves -> 200
{
 "data": {
  "status": "approved",
  "result": {
   "key_id": "key-d88e5c7e-55b4-412f-903b-427a719be0a9",
   "rotated": true,
   "affected": [
    "711039923aeedd0b73ed55b0656b7cac26316f812966124700ca8dc5a4ddb067",
    "c77476188f89e3ecbb0bf936548bf997834544983b6fb97fb3a9fbf1ddf83ce4",
    "7e04f441ef7043a3ae4cd7215127bbf0ad5aa92e2a8651a42f4396ade0bde20d"
   ],
   "revoked": [
    "711039923aeedd0b73ed55b0656b7cac26316f812966124700ca8dc5a4ddb067",
    "c77476188f89e3ecbb0bf936548bf997834544983b6fb97fb3a9fbf1ddf83ce4",
    "7e04f441ef7043a3ae4cd7215127bbf0ad5aa92e2a8651a42f4396ade0bde20d"
   ],
   "reissued": [
    "7e04f441ef7043a3ae4cd7215127bbf0ad5aa92e2a8651a42f4396ade0bde20d"
   ],
   "deferred": [
    "711039923aeedd0b73ed55b0656b7cac26316f812966124700ca8dc5a4ddb067"
   ],
   "failed": {
    "c77476188f89e3ecbb0bf936548bf997834544983b6fb97fb3a9fbf1ddf83ce4": "renewed but install failed: successor bdb7830b2b5e265742f774fce902c9d03df179fb428fdd77346975c36d0126d3 exists; target \"uat-down\" outcome=connect_failed ssh executor: dial kkw23cmp-down:22: dial tcp: lookup kkw23cmp-down on 10.89.1.1:53: no such host"
   },
   "steps": [
    "rotate",
    "flag",
    "revoke",
    "reissue"
   ],
   "errors": {}
  }
 }
}

=== 6. result ===
PASS: steps == [rotate, flag, revoke, reissue]
PASS: revoked contains all three fingerprints (3/3 = 100%)
PASS: reissued contains L1
PASS: deferred contains L2
PASS: failed reports L3 with its message: {'c77476188f89e3ecbb0bf936548bf997834544983b6fb97fb3a9fbf1ddf83ce4': 'renewed but install failed: successor bdb7830b2b5e265742f774fce902c9d03df179fb428fdd77346975c36d0126d3 exists; target "uat-down" o

=== 7. OCSP and CRL within 60 s of the approval ===
note: rotation replaced C's certificate (C0 != C1), as the spec expects
PASS: L1: openssl ocsp (-issuer C0, response verified against C0) -> revoked after 1 s
PASS: L2: openssl ocsp (-issuer C0, response verified against C0) -> revoked after 1 s
PASS: L3: openssl ocsp (-issuer C0, response verified against C0) -> revoked after 1 s
PASS: CRL /crl/C.crl lists L1 (E7E72AE08FBD9008AB840DC5A816E40D)
PASS: CRL /crl/C.crl lists L2 (AE8414BD86AEA5D0A46E835795151FB6)
PASS: CRL /crl/C.crl lists L3 (708641173D0E069574CDC40E95F0E75E)
PASS: CRL signature verifies against C's current certificate
info: CRL does not verify against the pre-rotation certificate C0 (signed by the new key)

=== 8. audit trail ===
PASS: audit has key.compromise
PASS: audit has alert.key.compromised
PASS: audit has alert.key.reissue_deferred
PASS: audit has alert.key.reissue_failed

=== 9. rotation failure: suspended CA => zero side effects ===
PASS: create CA C2 -> 201
PASS: issue leaf M under C2 -> 201
PASS: PUT /keys/K2/policy -> 200
PASS: suspend C2 (rotation refuses non-active CAs) -> 200
PASS: A proposes compromise of K2 -> 202
PASS: approve reports failure (503): {"error":"service_unavailable","message":"action failed: compromise force-rotate failed for key-a4518897-17db-4ac9-bd12-bd64919b06dd (nothing stamped, revoked or re-issued): ca re-key for a4518897-17d
PASS: no compromised_at on K2 (nothing stamped)
PASS: leaf M still good (nothing revoked)
PASS: no alert.key.* rows for K2 (0 before and after)

=== 10. summary ===
ALL STEPS PASSED
