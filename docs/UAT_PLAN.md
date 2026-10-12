# UAT Plan — proving the estate-management promise against real systems

## 1. Purpose

Kryptkeeper's stated goal (`docs/DECISIONS.md` D-106, `docs/sdlc/phase-0-ideation/VISION_V5.md`,
`docs/PRODUCT_SRS.md`) is CA-agnostic certificate estate management: discover every
certificate, renew and install it everywhere, agentless where possible. Unit and
httptest-fixture coverage proves the code paths are internally consistent; it does not
prove the product does what it claims against the systems a partner actually runs.

**Rule:** a surface counts as UAT-passed only with dated evidence against a real
external system, recorded as a `docs/STATUS.md` line and, where possible, a gated
live test under `tests/live/<surface>/` or a `*_live_test.go` file with an env
switch — following the `KK_LIVE_WINRM=1` pattern (`internal/agentdiscovery/live_winrm_test.go`).
A fake, a mock, or an httptest server is not evidence for this plan, no matter how
thorough its assertions.

## 2. Status matrix

| Surface | What "passed" means | Fixture needed | Status | Ticket |
|---|---|---|---|---|
| WinRM discovery + IIS install + issue→renew→install→verify | Full loop through the product API against a real Windows host | Windows 11 host, WinRM HTTPS | **passed** 2026-09-10 — STATUS.md line 242/246: `internal/agentdiscovery/live_winrm_test.go`, `KK_LIVE_WINRM=1`, 192.0.2.10 | done (W18-06/11/12/13) |
| Network TLS scanning (full/targeted/fast/deep) incl. TLS 1.3 ML-KEM | Deep scan detects real cipher/group, including hybrid PQ key exchange | Real TLS listener (Go server + IIS host) | **passed** 2026-08-20 — STATUS.md: deep scan of a Go TLS 1.3 server detected X25519MLKEM768; IIS host correctly reports TLSv1.3/X25519/no-ML-KEM | done (crypto-posture wave) |
| Postgres migrations + DR restore | Backup/restore drill completes against a real Postgres container | Postgres container | **passed** — `docs/ops/DR_RUNBOOK.md` | done |
| Smoke suite (binary self-test) | Real binary boots and answers its own API | none (self-contained) | **passed** — `tests/smoke/run.sh` | done |
| ACME with real clients | certbot and lego obtain/renew/revoke against the hub's `/acme` endpoint | certbot + lego containers | **passed** 2026-09-10 — `tests/live/acme/run.sh`, 28/28 checks: both clients' issue/renew/revoke/chain-verify/inventory(source=acme)/CRL/OCSP(good pre-revoke, revoked post-revoke) all PASS. 6 real hub defects found+fixed total: persistence, fake chain PEM, missing RFC 8555 Link/Replay-Nonce headers, missing issuer cert, CRL handler serving a stale lazily-cached list never regenerated on later revocations, and OCSP responder cache never invalidated on any revoke path — see docs/STATUS.md 2026-09-10 | done (W19-01) |
| SSH install to nginx/apache | Renewal executor pushes a renewed cert to a real sshd host and reloads the server | Ubuntu container, sshd, nginx, apache | **passed** 2026-09-10 — STATUS.md: `tests/live/ssh-install/run.sh`, nginx + apache + rollback all proven; 2 real hub defects found and fixed (SSH host-key-algorithm negotiation, verify-after-reload race) | done (W19-02) |
| Kubernetes push + cert-manager discovery | Push installs a Secret on a real cluster; discovery finds cert-manager-issued certs | kind cluster | **passed** 2026-09-11 — STATUS.md: W19-17 closed both gaps left open above (discovery API wiring for both providers, k8s push CA trust) and found/fixed two more real defects that were masking the original "not root-caused" empty-reply symptom (a canceled-context race in the scanner provider's async scan, and a global HTTP WriteTimeout too short for the k8s verify-retry window). Full rerun of `tests/live/k8s/run.sh` with kubectl proxy removed entirely: push installed_verified (independently confirmed via kubectl get + openssl fingerprint), negative case (write_failed, no secret), and k8s-certmanager discovery under BOTH scanner- and db-mode providers all PASS | done (W19-03) |
| kryptkeeper-agent (enrol, inventory, renewal) | Agent enrols, pushes inventory, executes a renewal task, against the real hub API, **with the hub in its default TLS mode** | Linux container running the agent binary | **done** — full enrol/inventory/renewal proven live (`tests/live/agent/`, 18/18 asserted steps) with the hub serving TLS (self-issued cert) and the agent trusting it via `KRYPTKEEPER_HUB_CA_CERT_FILE` (W19-32) — no more `KRYPTKEEPER_TLS_DISABLE` pin; W19-13's `KRYPTKEEPER_BASE_URL`/identifiers fixes plus a W19-04-rerun fix for a reload/verify race in `internal/agentinstall` (installer.go) closed the loop; hub audit shows `agent.renewal_result` outcome=success, nginx serves the renewed leaf issued by "UAT Root CA" — see docs/STATUS.md 2026-09-11 (W19-32) | W19-04, W19-32 |
| EST/SCEP/CMP with real clients; OCSP/CRL after real revocation | openssl `cmp`, sscep/EST client complete enrolment; `openssl ocsp` reflects a real revocation | openssl, sscep or EST client | **passed** 2026-09-11 — EST over TLS (W19-14), SCEP RSA CA (W19-15), CMP PBM (W19-16), OCSP/CRL (W19-05) | W19-05 |
| AD LDAP sync | Sync pulls real users/groups from a domain controller | Samba AD container | **blocked** on this host 2026-09-10 — `tests/live/ad-ldap/run.sh` built and run; Samba `domain provision` panics ("Security context active token stack underflow") because `security.*` xattrs are refused under this podman-machine's container storage even `--privileged` (verified directly with `setfattr`); not a kryptkeeper defect. Fixture's sync/cert/gpo-check/negative steps are written, unexercised — see docs/STATUS.md | W19-06 |
| Istio/Linkerd discovery | Mesh certs discovered from a real mesh control plane | kind cluster + Istio/Linkerd | **passed** 2026-09-11 — STATUS.md: `tests/live/mesh/run.sh` re-run after W19-22 landed: ALL PASS. Real Linkerd (edge-26.6.3) issuer + real Istio (istioctl 1.31.0) CA secret reads land in `GET /api/v1/discovery/endpoints` with correct fingerprints (matching independent kubectl+openssl ground truth) and the real RBAC 200/403 split holds, after fixing two real hub defects: W19-20 (mesh discovery had no K8s API-server CA trust) and W19-22 (the `endpoints` table's `port BETWEEN 1 AND 65535` CHECK rejected every K8s-secret-sourced mesh result outright, and `upsertScanResults`'s one-transaction-per-sweep design meant that single failure discarded the ENTIRE sweep — mesh discovery had silently never landed anything in inventory since it was wired, W7-06/W12-04, for any cluster, ever). The negative RBAC case now passes too: the scheduler logs a nonzero source-error count AND the denied secret is visible via `GET /api/v1/discovery/endpoints` as an endpoint carrying a `discovery-error: ... HTTP 403` issue with zero mapped certs — a caller of the product API sees the permission denial directly and cannot mistake it for a successful read | W19-09 (depends on W19-03) |
| WSTEP/XCEP autoenrollment | A domain-joined Windows client completes MS-WSTEP/XCEP enrolment | Domain-joined Windows client | Machine context: GPO autoenrollment and renewal on lab-win11 (W18-08). User context: `tests/live/wstep` as a domain user over real Kerberos, and GPO autoenrollment at a real user logon on lab-win11, both 2026-10-08 | W19-10 |
| F5 / Citrix push | Renewal executor installs onto real F5/Citrix appliances | F5/Citrix hardware or trial VM | fakes only — **blocked** on hardware | W19-11 |
| AWS/GCP/Azure KMS | Key operations succeed against real cloud KMS | Cloud accounts | fakes only — **blocked** on accounts | W19-12 |

Counts: **13 passed**, **0 partial**, **0 todo**, **4 blocked** (W19-06 AD on this host, W19-10 WSTEP lab, W19-11 F5/Citrix hardware, W19-12 cloud KMS accounts).

Last regression run: 2026-09-11 on W19-33's commit (branch `kk/w19-33-cert-source-check`) — the CMP-inventory defect the previous run below found (`certificates.source` CHECK constraint never included `'cmp'`/`'tls-listener'`) is fixed by migration `000060_certificates_source_vocabulary`: acme 28/28, agent 17/17, compose 5/5, k8s 31/31, mesh 18/18, notifications 18/18, pkcs11 23/23, ssh-install 21/21, tls 13/13 all PASS; ad-ldap known-blocked (Samba provisioning, W19-06); **protocols 33 PASS, 0 FAIL — ALL STEPS PASSED**, including the CMP-inventory check that previously failed. All fixtures now green on this commit except the documented W19-06 block. See `docs/STATUS.md` 2026-09-11 W19-33 and W19-31 (closing update) for full detail; prior history: d84daa7 (protocols TLS fix, 28/29) and 78d4866 (all-fixtures baseline) below.

## 3. Execution order and rationale

Ordered by fixture cost (cheapest/most container-native first) and dependency, so
early tickets retire risk and infrastructure (kind, container patterns) that later
ones reuse.

1. **ACME** — certbot and lego in containers. Cheapest fixture (no VM, no domain),
   and the ACME server is the most-used protocol surface; W18-14's finding that
   ACME issuance never persists to the certificates table makes this doubly
   worth exercising now.
2. **SSH install to nginx/apache** — Ubuntu container with sshd. This is the
   *only* install path the scheduled renewal sweep actually executes today
   (`docs/ops/PILOT_KNOWN_GAPS.md` F4); proving it live closes the gap between
   "what auto-renew claims" and "what auto-renew does."
3. **Kubernetes push + cert-manager discovery** — kind cluster. Establishes the
   kind fixture that W19-09 (mesh) reuses.
4. **kryptkeeper-agent** on a Linux container — enrol, inventory push, renewal
   task. The agent path is entirely unverified against a real host; needed
   before agent-based Windows/macOS claims can be trusted either.
5. **EST/SCEP/CMP/OCSP/CRL** with real clients — highest protocol-surface count
   per fixture (openssl covers cmp, ocsp and, with sscep, scep).
6. **AD LDAP sync** — Samba AD container, self-contained, no external lab needed.
7. **Notifications** — Slack webhook, MailHog/Mailpit, webhook receiver for SIEM.
   Low risk, but currently zero live evidence for any alerting path a pilot
   partner will depend on operationally.
8. **PKCS#11 via SoftHSM2** — software HSM, no real hardware dependency, but
   exercises a code path (`internal/keystore`) that is otherwise fakes-only and
   security-sensitive.
9. **Istio/Linkerd discovery on kind** — depends on W19-03's kind fixture.
10. **WSTEP/XCEP with a domain-joined Windows client** — blocked on the owner's lab
    (no domain controller / joined client exists yet); ordered last among the
    "real but hard" items because F1 in `PILOT_KNOWN_GAPS.md` already discloses
    it as unverified and the WinRM/IIS win (item 0, already passed) reduces
    urgency.
11. **F5/Citrix** — blocked on hardware access.
12. **AWS/GCP/Azure KMS** — blocked on cloud account provisioning.

## 4. Evidence template

Each ticket, on completion, appends ONE line to `docs/STATUS.md` in the existing
format:

```
YYYY-MM-DD W19-NN done — <surface> proven live: <what was run, against what
real system, what the outcome was (counts, verdicts, before/after)>. <defects
found and fixed, if any>. Gated live test: <path> (<ENV_VAR>=1), N/N green.
go test <pkgs>, make lint <status>.
```

It must name: the real system exercised, the specific command/API call proving
it (not "it worked" — the observable result), any defects found along the way
(these are often the actual value of the ticket, per the WinRM precedent), and
the gate status (go test, make lint, and openapi drift where relevant).

## 5. Host/fixture inventory

- **Windows lab host** `192.0.2.10` — WinRM HTTPS on 5986, IIS, local user
  `<local-user>`. Already in use for the passed WinRM/IIS surface; available for
  W19-10 once a domain controller and domain join exist on the same lab.
- **Container fixtures** (Podman/Docker per `container-expert`/`containers`
  skill conventions already in this repo): certbot, lego, Ubuntu+sshd,
  nginx, apache, kind, Samba AD, MailHog/Mailpit, SoftHSM2, Istio/Linkerd on
  kind.
- Fixture scripts live under `tests/live/<surface>/` with a README each,
  documenting how to bring the fixture up, what env switch gates the live
  test, and how to tear it down. **Do not write these scripts now** — each
  W19 ticket builds its own fixture and test as part of its acceptance
  criteria.
