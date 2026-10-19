# Live results: SSH agentless install, HAProxy and Tomcat (W27-08, v0.15)

- Harness: `bash tests/live/ssh-install/run.sh` (podman 5, arm64 podman machine, macOS)
- Date: 2026-10-16
- Base commit: 5ea94e32 (branch kk/w27-c) plus the W27-08 harness change
- Wall time: 3m06s (image build included)
- Result: **ALL PASS**, `checks: 43 passed`, 4 servers (nginx, apache, haproxy, tomcat)
- Tomcat: 10.1.61 from archive.apache.org, sha512 pinned in the Containerfile; JRE openjdk-21; HAProxy 2.8.16


## What was proven

| Server | positive install | served within 60 s of reload | verify-mismatch rollback | forced config-test failure |
|---|---|---|---|---|
| nginx | installed_verified | PASS (0 s) | PASS | not applicable (not in W27-08 scope) |
| apache | installed_verified | PASS (0 s) | PASS | not applicable |
| haproxy | installed_verified | PASS (0 s) | PASS | PASS: `config_test_failed`, old serial served, `haproxy.pem` sha256 unchanged |
| tomcat | installed_verified | PASS (0 s) | PASS | PASS: `config_test_failed`, old serial served, `kk.p12` sha256 unchanged |

"0 s" is the whole-second delta between the install response and the host-side
independent `openssl s_client` read matching `new_fingerprint`; the hub itself
had already verified over the container network inside the response.

Served fingerprints (sha256) after the positive install:
haproxy `d456e4fd5393e8a2061140c6a7f98a997a2816dd88b9a30b53568ef924ee5466`,
tomcat `8881ad6498dc87ca2d638847b44021734defb108177b843e9e01cc366ee1de58`,
nginx `7991ea92b4a5f5706ba4dc82e70764c6d546010b6adae43dfedfc0aa0de661ab`,
apache `6d0bb6e609776fea60e681faca6d0ce82264f90ad05d0a6b82c3eb27071c33a9`.
Config-test case file hashes (before == after): haproxy
`9974107adf398dff2009070fd20d2efacabd53547013ee860fec277d86d42c6c`, tomcat
`b327e0244061bf03c5224c07cff1b17cb68025d197629f45bfd29cc4a505f4a4`.

The fixture Tomcat keystore password appears 0 times in the hub container log
and in the audit log (`/api/v1/audit?limit=1000`).

## Observation (not a failure)

When `catalina.sh configtest` fails, `install_detail` carries Tomcat's full
Java stack trace (about 4 KB). The password is not in it, but the detail is
noisy for operators; consider trimming to the first SEVERE/WARNING lines.

## PASS lines (verbatim from the run, temp paths elided)

```
PASS: keypair generated in <tmp>
PASS: image built
PASS: network kk-uat-ssh-net-857f1e
PASS: container kk-uat-ssh-nginx-857f1e up
PASS: container kk-uat-ssh-apache-857f1e up
PASS: container kk-uat-ssh-haproxy-857f1e up
PASS: container kk-uat-ssh-tomcat-857f1e up
PASS: all four containers reachable (ssh + tls)
PASS: captured host keys for pinning
PASS: placeholder fingerprints: nginx=fb30c900c83ff574b771d0d785cd58ebca869e4c6f92ecac5af5153d46f82632 apache=fb30c900c83ff574b771d0d785cd58ebca869e4c6f92ecac5af5153d46f82632 haproxy=fb30c900c83ff574b771d0d785cd58ebca869e4c6f92eca
PASS: hub built (linux/arm64)
PASS: hub image built
PASS: hub container kk-uat-ssh-hub-857f1e up
PASS: hub answering on http://127.0.0.1:64122
PASS: root CA: a7485d3f-4dc7-41e5-8a5d-64ccc969ab06
PASS: template: tpl-uat-ssh-server-1792168367480450059
PASS: [nginx] credential: cred-fd62e6f234f587964396b97c19091556
PASS: [nginx] target: target-1de284e7a409a112de6aae5dc9e7c84a
PASS: [nginx] issued: cfcae32cbd81d78ef274defb6c891ef86a1d0a7c663b482fb32a6e8c931a1e6d
PASS: [nginx] served leaf matches new_fingerprint (7991ea92b4a5f5706ba4dc82e70764c6d546010b6adae43dfedfc0aa0de661ab) 0s after the install response (bound 60s)
PASS: [nginx] rollback proven: still serving prior good cert (7991ea92b4a5f5706ba4dc82e70764c6d546010b6adae43dfedfc0aa0de661ab)
PASS: [apache] credential: cred-58216af835b1d452e0b034da1ffee04f
PASS: [apache] target: target-d9fa1f75959558f79e9b4f3b79286655
PASS: [apache] issued: 949f875fd9e863eb3cbb176ed8b57d08a04d925f97374931a0be6eec0bacece7
PASS: [apache] served leaf matches new_fingerprint (6d0bb6e609776fea60e681faca6d0ce82264f90ad05d0a6b82c3eb27071c33a9) 0s after the install response (bound 60s)
PASS: [apache] rollback proven: still serving prior good cert (6d0bb6e609776fea60e681faca6d0ce82264f90ad05d0a6b82c3eb27071c33a9)
PASS: [haproxy] credential: cred-3aaecd08e37f8865e95c8954b17bb3af
PASS: [haproxy] target: target-2d555de362a351abb894a55d172ba77f
PASS: [haproxy] issued: 4c69442c849279ca06cbd0f87a441d5f67008c10d2cb45f9901db78e21478349
PASS: [haproxy] served leaf matches new_fingerprint (d456e4fd5393e8a2061140c6a7f98a997a2816dd88b9a30b53568ef924ee5466) 0s after the install response (bound 60s)
PASS: [haproxy] rollback proven: still serving prior good cert (d456e4fd5393e8a2061140c6a7f98a997a2816dd88b9a30b53568ef924ee5466)
PASS: [haproxy] config_test_failed reported
PASS: [haproxy] old serial still served after config-test failure (d456e4fd5393e8a2061140c6a7f98a997a2816dd88b9a30b53568ef924ee5466)
PASS: [haproxy] /etc/ssl/kk/haproxy.pem restored byte-for-byte (sha256 9974107adf398dff2009070fd20d2efacabd53547013ee860fec277d86d42c6c)
PASS: [tomcat] credential: cred-656bd9357bffafbff27df176e11fba54
PASS: [tomcat] target: target-5cabd50fb1a4b8048bcb44da79243804
PASS: [tomcat] issued: 24bb7df28c72c1d7c57fce7ee562cc12ed625e880d1e3c48b6e4b65f6a66bb3f
PASS: [tomcat] served leaf matches new_fingerprint (8881ad6498dc87ca2d638847b44021734defb108177b843e9e01cc366ee1de58) 0s after the install response (bound 60s)
PASS: [tomcat] rollback proven: still serving prior good cert (8881ad6498dc87ca2d638847b44021734defb108177b843e9e01cc366ee1de58)
PASS: [tomcat] config_test_failed reported
PASS: [tomcat] old serial still served after config-test failure (8881ad6498dc87ca2d638847b44021734defb108177b843e9e01cc366ee1de58)
PASS: [tomcat] /opt/tomcat/conf/kk.p12 restored byte-for-byte (sha256 b327e0244061bf03c5224c07cff1b17cb68025d197629f45bfd29cc4a505f4a4)
PASS: keystore password appears 0 times in hub log and audit
checks: 43 passed
ALL PASS
```
