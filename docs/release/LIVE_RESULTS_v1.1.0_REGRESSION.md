# Kryptkeeper 1.1.0 — live lab regression sweep

Gap P17: the 1.0.0 lab sweep ([LIVE_RESULTS_v1.0.0.md](LIVE_RESULTS_v1.0.0.md), "Harnesses (tests/live)")
repeated on the v1.1.0 tag.

- Date: 2026-10-26
- Code under test: `66b2f9c002fab8c30f125a9cd2232acee0347cd6` (tag v1.1.0), synced to the runner by git bundle
- Runner: lab-runner (hypervisor `hypervisor`, VM 123, 8 cores, Ubuntu 24.04 amd64), podman 4.9.3 as main engine
  (`podman build` routed to podman 5 by `~/shim`), rootful podman wrapper for ad-ldap, kind 0.30, go 1.26.10 (go.mod
  toolchain), OpenSSL 3.5.4 and cosign 3.1.3 under `/opt` for pqc and codesign-oidc. Harnesses ran sequentially
  (`batch2.sh`), from a cold Go module cache for the first harness.
- Mac (compose, sse, ha, and one pqc-wave cross-check): Darwin arm64, podman 6.1.3, go 1.27.1, shared with the CI
  runner (not touched).
- Not run in this pass: `make lint`, `go test ./...`, UI tests (the 1.0.0 "Gate on main" table). The smoke suite was run.
- Result rule: PASS means the harness exited 0 on this sha in this pass. A harness that failed first and passed on a
  rerun is marked PASS (rerun) and the first failure is listed below. Nothing here is carried over from 1.0.0.

## Harnesses (tests/live)

| Area | Harnesses | Result |
|---|---|---|
| Protocols | protocols, tls, sshca, acme, acme-dns-providers (rfc2136, wildcard, long wait), upstream-renew | PASS (protocols and acme PASS on rerun; first runs failed, see Failures) |
| Let's Encrypt | acme-upstream (LE staging, Cloudflare dns-01, SSH install, verify, zone clean; token copied to the runner for the run and deleted after) | PASS (152 s, "ALL STEPS PASSED", no `_acme-challenge` left) |
| CAs and keys | ca-hierarchy, ca-offline-root, ca-revoke, ca-rollover, ceremony, key-compromise, key-inventory, pkcs11, escrow-byok, kms-aws, kms-azure, kms-gcp, vault | PASS (ca-hierarchy and ca-revoke PASS on rerun) |
| Code signing | codesign, codesign-oidc (cosign 3.1.3, OpenSSL 3.5) | PASS |
| PQC | pqc (OpenSSL 3.5 ML-DSA interop) | PASS |
| PQC | pqc-wave | FAIL on the runner (hub built with go 1.26.10); PASS on the Mac (go 1.27.1). See Failures |
| Discovery | discovery, discovery-protocols, ssh-discovery, agentless-sudo (helper, nopasswd, password), fingerprint-corpus, cloud-inventory | PASS |
| Discovery | inventory-sources | FAIL (harness rot, entrust fixture). See Failures |
| Agents and install | agent, autopilot (29/29), ssh-install, rollout, plugins, packages | PASS |
| Load | revocation-bench | PASS |
| Load | storm full profile | FAIL by its own gate (script exit 1), same documented shape as before; both legs finalize 2000/2000 with 0 duplicates and 0 late violations. See Failures |
| Identity and governance | sso, keycloak, spiffe, issuance-approval, mcp, ad-ldap (Samba AD, rootful), migration (live migration test) | PASS |
| Notifications and ops | notifications, evidence-mail, siem, itsm, slo, delivery-cloud, egress (`--short`, 7/7; the full 10 min profile was not run), terraform | PASS |
| Kubernetes | k8s, certmanager, helm-kind, helm-ha, mesh, istio-mtls, promote-rollback, airgap (`KK_AIRGAP_LOCAL_IMAGES=1`, 60 s capture) | PASS |
| Compose | compose, sse (600 s stream), ha (chaos, Mac podman) | PASS |
| Smoke | `tests/smoke/run.sh` | 446 / 446 passed (1.0.0: 445) |

Per-run wall times and exit codes are in the runner's `~/runs/v11`, `~/runs/v11-special`, `~/runs/v11r`.

## Failures and how they were classified

| Harness | First result | Classification | Evidence |
|---|---|---|---|
| protocols | rc 1 after 55 s, "hub did not come up" (curl to :8096 refused for the whole wait) | Environment (cold first build: go toolchain and module download at the start of the sweep) | Rerun on the same sha: PASS in 141 s |
| acme | rc 1: lego "obtain certificate" timed out at 599 s, 25 passed / 1 failed | Environment (podman 4.9 DNS flake between containers; the harness already retries lego http-01 for this) | Rerun: PASS 110 s. Not proven by a repeat failure; see the branch section, where the same harness failed once on another sha and passed on rerun |
| ca-hierarchy | rc 1: `podman network create ... 172.29.231.0/24` refused, "compose up failed" | Environment (an orphan network `kkw1923live_default` from an earlier compose run held the subnet) | Orphan removed; rerun PASS 106 s |
| ca-revoke | rc 1: ACME failed "but not for the revoked CA" after an authorization deactivation | Unclassified flake, most likely the same container-DNS problem as acme (the failed run was a http-01 solve timing out); not root-caused | Rerun: PASS 90 s |
| pqc-wave (runner) | rc 1 twice. Run 1: install verify "lookup kkw31-11-ep-a: i/o timeout". Run 2: hub log `verify dial ... tls: handshake failure` on all three ML-DSA endpoints | Environment (toolchain): the hub binary was built with go 1.26.10 on the runner; the same harness on the same sha, hub built with go 1.27.1 on the Mac, passed (ALL PASS, 21 s). `internal/agentinstall/verify.go` is unchanged since 1.0.0 and the 1.0.0 sweep ran the older harness that only checked `delivery_unsupported`, so 1.0.0 never exercised this path on the runner | Ranked causes: (1) Go 1.26 TLS client cannot complete a handshake with an ML-DSA-only server certificate while 1.27 can (inferred from the two runs, not from Go source); (2) container DNS flake (explains run 1 only); (3) product regression in the verify dial (ruled out as the main cause by the Mac pass). **Update 2026-10-26: cause (1) confirmed.** Go 1.26 `crypto/tls` has no ML-DSA signature schemes; a minimal `tls.Dial` and `run-w40.sh` both fail on go1.26.10 and pass on go1.27.1. Fixed by moving the build to Go 1.27.1 (PR #192). **Original open question for release owners:** the Dockerfile builds the shipped hub with `golang:1.26-alpine`; if cause (1) is right, a shipped hub image cannot verify an ML-DSA delivery over TLS. Not verified here |
| inventory-sources | rc 1: entrust sync "entrust credential must be {username, api_key, client_cert_pem, client_key_pem}" | Harness rot: W36-11 (`ceb153f8`) rewrote the Entrust source to real mTLS credentials; `tests/live/inventory-sources/run.sh` still posts `{"api_key": ...}` against a plain-HTTP fixture. The same harness also failed in the 1.0.0 sweep log. Sectigo, AWS PCA and GCP CAS legs reported no FAIL; DigiCert sandbox SKIP (no `KK_DIGICERT_API_KEY`) | Fix needs a TLS fixture with a client cert; not done here |
| storm full | rc 1 | Known, documented: the strict "zero CA limit violations" criterion fails (8 in leg A, 18 in leg B) and leg A took 375 s against a 360 s goal. Leg A 2000/2000, leg B 2000/2000, 0 duplicates, 0 late violations, successors present. Leg B2 (kill -9, informational) finalized 1802/2000 | Matches `tests/live/storm/README.md` ("the script still exits 1"). This is not a clean PASS; it is no worse in shape than the 1.0.0 record, but the leg A time over goal (375 vs 360 s) was not investigated |

No product regression was found. Nothing was fixed in product code.

## Not run

| Item | Why |
|---|---|
| Windows domain harnesses (GPO autoenroll, WSTEP matrix, WinRM discovery, IIS/RDP/SQL install, Windows agent MSI) | NOT RUN. They need domain credentials, GPO/listener changes on the lab domain VMs and a Kerberos-enabled hub. The domain VMs were already running (lab-dc01, lab-ca01, lab-win11, lab-ws22) and were not touched; no VM was started or stopped by this pass |
| macOS keychain, scep-appliance, F5/NetScaler, real cloud KMS | As in 1.0.0 (no hardware, accounts or Mac VM in this pass) |
| egress full profile, ha `--soak` | Short egress profile only; ha chaos only |
| credential-sources, ct, trust-store, upstream-cas, images, wstep (Go live test), run-w40 pqc legs | Not in the 1.0.0 harness table; not run here |
| `make lint`, `go test ./...`, UI suites | Not part of the lab sweep; not run in this pass |

## Branch head after the key-usage change

Branch `fix/v1.1-trust-leaks`, head `060e651bcb54e3de70f36e48cce0fb941cf8c05a` (on top of v1.1.0 `66b2f9c0`; changes issued
leaf key usage, the time-stamping EKU and ocsp-nocheck in `internal/ca`). Same runner and rules; only the two
harnesses that cover issuance across the protocols were rerun.

| Harness | sha | Result |
|---|---|---|
| protocols (ACME, EST, SCEP, CMP, OCSP, CRL, policy refusal) | 060e651b | PASS (157 s) |
| acme (certbot, lego) | 060e651b | First run FAIL: lego renew, three http-01 fetch failures, 24 passed / 1 failed (401 s). Second run PASS, 28 passed / 0 failed (364 s) |
| Windows WSTEP and autoenrollment (including an ECDSA template) | 060e651b | NOT RUN, same reason as above: needs domain credentials, GPO and a Kerberos hub on the lab domain; the ECDSA template question was therefore not exercised on Windows |

The acme harness now has one failure and one pass on each of 66b2f9c0 and 060e651b, so the branch is not distinguished
from main by it. The lego failures on both shas are in the container-network http-01 fetch, not in a certificate check.
A Windows chain-validation pass is still needed before treating the key-usage change as proven for Windows clients.

## Lab state after the run

The runner clone `~/kk-v1` was left at 66b2f9c0. Run records from the 1.0.0 sweep (dirty files, ceremony record) are in
`~/runs/keep/v10-dirty`. The Cloudflare token was removed from the runner. Leftover `kk-airgap-*` containers and
a stray `/tmp/kk-uat-mesh-neg-hub` hub process (pre-existing, from 1.0-era mesh runs) were left in place.
