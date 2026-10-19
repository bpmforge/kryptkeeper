# Kryptkeeper 1.0.0 — live lab results

Final lab pass for 1.0.0, run 2026-10-18 on `main` (sweep at 78494f48 and 2878b6e5; the
only later merges, PR 169 and PR 170, were re-verified by the harnesses they touch).
Lab: hypervisor `hypervisor`; runner lab-runner (Ubuntu 24.04 amd64, podman 4.9, kind 0.30);
Windows domain corp.example.test (DC WS2025, Enterprise CA, Windows 11 25H2, Server 2022 member);
hub lab-hub on the main build. Per-area detail: [LIVE_INVENTORY_v1.md](LIVE_INVENTORY_v1.md),
[LIVE_RESULTS_v1_WINDOWS.md](LIVE_RESULTS_v1_WINDOWS.md),
[LIVE_RESULTS_v1_LINUX_COVERAGE.md](LIVE_RESULTS_v1_LINUX_COVERAGE.md); security:
[../security/V1_FINAL_SCAN_2026-10-18.md](../security/V1_FINAL_SCAN_2026-10-18.md) (verdict CLEAN).

## Gate on main

| Check | Result |
|---|---|
| `make lint` | 0 issues |
| `go test ./...` | 86 packages ok (93 incl. no-test packages), 0 failures |
| Live-Postgres suite (`internal/bootstrap -run Postgres`) | ok |
| UI `tsc -b`, `vite build`, vitest | pass; 1018 tests |
| OpenAPI drift | none (238 routes / 293 paths) |
| Smoke (`tests/smoke/run.sh`) | 445 / 445 |
| the self-hosted forge CI | green on PR 167, 169; PR 170 green except e2e-smoke, which the runner outage killed and could not be rerun (see main CI) |

## Harnesses (tests/live)

| Area | Harnesses | Result |
|---|---|---|
| Protocols | protocols (ACME, EST, SCEP, CMP, OCSP, CRL, policy refusal), tls, sshca, acme, acme-dns-providers (RFC2136, wildcard, long wait), upstream-renew | PASS |
| Let's Encrypt | acme-upstream (LE staging, Cloudflare dns-01, SSH install, verify, zone clean) | PASS (first green run) |
| CAs and keys | ca-hierarchy, ca-offline-root, ca-revoke, ca-rollover, ceremony, key-compromise, key-inventory, pkcs11 (SoftHSM2, dual control), escrow-byok, kms-aws/azure/gcp (emulators), vault | PASS |
| Code signing | codesign, codesign-oidc (cosign 3.1.3, OpenSSL 3.5) | PASS |
| PQC | pqc (OpenSSL 3.5 ML-DSA interop), pqc-wave | PASS |
| Discovery | discovery, discovery-protocols, ssh-discovery, agentless-sudo (helper, nopasswd, password), fingerprint-corpus (17/17), cloud-inventory, inventory-sources | PASS |
| Agents and install | agent (JKS, PKCS#12, kubeconfig), autopilot (29/29), ssh-install (nginx, Apache, HAProxy, Tomcat PKCS#12 and JKS), rollout, plugins (mock device), packages | PASS |
| Load | storm full profile 2000/2000 in both legs; revocation-bench | PASS (see storm README for the documented rate-limit and lease notes) |
| Identity and governance | sso, keycloak, spiffe, issuance-approval, mcp, ad-ldap (Samba AD, rootful), migration (200/200) | PASS |
| Notifications and ops | notifications, evidence-mail, siem, itsm, slo, delivery-cloud (vault leg), egress, terraform | PASS |
| Kubernetes | k8s, certmanager, helm-kind, helm-ha (failover, PDB drain), mesh, istio-mtls, promote-rollback, airgap | PASS |
| Compose | compose, sse, ha (Mac podman) | PASS |

Product bugs found and fixed by this pass (all with tests): Postgres pool exhaustion
(122 → 39 connections); SQLite refresh/write deadlock; takeover reverted by a stale refresh;
key operations answering 403 and leaking DB details when the policy store was down (now
503); XCEP advertising 2048-bit keys under a 3072 policy (GPO autoenroll refused since
v0.10); XCEP ignoring family allow-lists; two WinRM argument-encoding bugs that broke all
agentless Windows discovery and IIS installs; Windows agent missing `LocalMachine\My`;
Linux agent keystore and kubeconfig discovery lost after W34-09; privilege-finding paths
keeping a curly quote; duplicate UI type field breaking the production build.

## Windows

| Check | Windows 11 25H2 | Server 2022 |
|---|---|---|
| GPO machine autoenroll (RSA-3072) | PASS | PASS |
| WSTEP renewal with predecessor | PASS | PASS |
| Template filter (machine vs user) | PASS | PASS |
| Clock skew > 5 min refused | PASS | PASS |
| WinRM discovery | — | PASS (24 certs) |
| IIS push, verify, rollback | — | PASS |
| Windows agent MSI (enroll, store + file discovery, no key egress, install refusal, uninstall) | — | PASS |

User-context WSTEP (Kerberos, XCEP, WSTEP) also passes against the main build.

## Not proven in this lab

| Item | Why |
|---|---|
| F5 BIG-IP, Citrix NetScaler | Real appliances not available for free; mock device only |
| Real AWS KMS, Azure Key Vault, GCP KMS | No cloud accounts; emulators only |
| scep-appliance (vendor device) | Needs a vendor appliance |
| WSTEP on Windows 10, Server 2019 | No ISO in the lab |
| WSTEP on Server 2025 as a member | Only the DC and CA run Server 2025 |
| macOS Keychain | Last proven 2026-10-15 on a tart VM; not rerun |

## Roadmap (deferred from 1.0.0)

Everything deferred during this pass is on the public [roadmap](../ROADMAP.md), including:
SQL Server, Exchange and RDP install modes (W35-02..04); NSS databases; the CA "slow down"
signal across restarts (W35-01); automatic destruction of retired CA keys; partner-hardware
proofs (F5, Citrix, real cloud KMS); Windows autoenrollment on Windows 10, Server 2019 and
Server 2025; Windows-agent installs to nginx, Apache and Tomcat on Windows; ECDSA keys over
XCEP; rollout groups stored on the hub; tenant ownership for CA-less certificates, agents
and workload identities; tenant name in logs; refresh token storage.
