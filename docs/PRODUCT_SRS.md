# Kryptkeeper — Product & Leadership Requirements (golden-state)

**Date:** 2026-07-15 · the product-capability requirements for reaching "golden state" and
CLM category leadership. Basis: `docs/work/PRODUCT_ENHANCEMENTS.md` (verified code reality) +
the 2026 competitive brief (`docs/research/CLM_LEADERSHIP_2026.md`). `FR-P<n>` namespace; each
maps to a golden-state board ticket. Tiering follows the competitive brief: T1 = table-stakes
(absence disqualifies), T2 = leader-defining differentiator, T3 = whitespace leapfrog.

| ID | Tier | Requirement | Acceptance sketch | Traces | Status |
|---|---|---|---|---|---|
| FR-P1 | T1 | Notifications actually deliver on ALL of {email, Slack, PagerDuty, webhook, SIEM} | a triggered alert reaches a real endpoint on each channel; delivery status is recorded; the log-only stub is gone | PE-1, D-040 | shipped (W4-01, W5-08 — 2026-07-28) |
| FR-P2 | T1 | The fleet renewal scheduler renews hub-managed/ACME-eligible certs, not only logs | the scheduler invokes issuance for in-threshold certs it owns; a renewed cert appears with a new NotAfter; failures route to the queue (R-E1) | PE-2, D-041 | shipped (W4-02, W4-05, S-35, W5-13 — 2026-08-18) |
| FR-P3 | T2 | PQC migration has an EXECUTE step: one action re-issues a wave's certs to ML-DSA/hybrid | invoking migrate-wave re-issues each member to PQC and advances tracked progress; partial failures are recorded, not silent | PE-3, D-042 | shipped (W4-03, W4-07, W4-08, W4-09, W4-10 — board done, no STATUS line, <=2026-07-28 baseline) |
| FR-P4 | T1 | ACME supports External Account Binding (EAB) — shipped free | an ACME account can be gated behind an EAB credential; unbound enrollment is rejectable by config | D-043 (free-EAB wedge) | shipped (W4-04, W1-08, W1-09 — 2026-07-30) |
| FR-P5 | T1 | Last-mile install covers ALL of {nginx, apache, HAProxy, IIS} with test+reload+verify+rollback | each target: config-test, reload, re-handshake verify, rollback on mismatch; a per-target integration test passes | PE-4, D-044 | shipped (W5-01, W5-02 — 2026-08-19); IIS live-proven 2026-09-10 |
| FR-P6 | T1 | Last-mile push to network/appliance targets: F5 BIG-IP and Citrix | a renewed cert is pushed + bound on F5 and Citrix via their APIs; verify-after-push confirms serving | PE-4, D-044 | shipped (W5-03 — 2026-08-19) |
| FR-P7 | T1 | Kubernetes + service-mesh (Istio) cert push | renewed certs land as k8s secrets / mesh identities; cert-manager issuer already covers native k8s | D-045 | shipped (W5-04 — 2026-08-19) |
| FR-P8 | T1 | Issuance-time policy engine: enforce allowed algorithms, key sizes, validity, CA constraints | a request violating policy is refused at issuance with a cited rule; policy is data-driven, not compile-time | D-046 | shipped (W5-05 — 2026-08-19) |
| FR-P9 | T2 | MCP write surface covers ALL of {issue, renew, revoke, rotate} as approval-gated proposals | each action is proposable via MCP and executes only after human approval; none mutates directly | PE-5, D-047 | shipped (W5-06 — 2026-08-19) |
| FR-P10 | T1 | HA / clustering: schedulers and issuance are safe to run on ≥2 replicas | leader election or a scheduler lock prevents double-run; a killed leader fails over; no duplicate renewals/alerts | PE-9, D-048 | shipped (W6-01 — 2026-07-28) |
| FR-P11 | T1 | Enterprise auth: SSO (SAML/OIDC) + SCIM user/group provisioning | operators log in via SSO; SCIM creates/deprovisions accounts + group→role mapping | PE-10 kin, D-049 | shipped (W6-02, W6-09, W6-10, W6-11, W6-08, W6-12, W6-13 — 2026-08-19) |
| FR-P12 | T1 | HSM/KMS integration completed (PKCS#11 + cloud KMS) for CA + PQC keys | a CA key and an ML-DSA key live in an HSM/KMS and sign without leaving it; the scaffolding paths are finished | D-050 | shipped (W9-01, W9-02 — 2026-08-19) |
| FR-P13 | T1 | Key escrow / backup / recovery workflow | a CA/private key can be escrowed encrypted and recovered under dual control; an EXECUTED recovery drill is documented | D-051, G-8 kin | shipped (W9-12 — 2026-08-19) |
| FR-P14 | T2 | CBOM: cryptographic bill of materials with CycloneDX export | inventory (certs + keys + algorithms + protocols) exports as valid CycloneDX CBOM JSON; always-current, framework-mappable | D-052 | shipped (W6-05 — 2026-08-19) |
| FR-P15 | T2 | CT-log monitoring: detect rogue/shadow certs for owned domains | ingest CT logs for configured domains; a cert not in inventory raises a finding; feeds the alerting channels | D-053 | shipped (W6-06 — 2026-08-19) |
| FR-P16 | T2 | Cross-signing / multi-issuer in-place key rotation | a CA can be re-keyed and cross-signed for a zero-downtime rollover; both chains validate during transition | D-054 | shipped (W6-07 — 2026-08-19) |
| FR-P17 | T2 | SPIFFE/SPIRE workload identity + node/workload attestation | attested workloads receive short-lived SVIDs; extends the v2.1 REST mint with the gRPC Workload API + attestation | D-055, v2.1 follow-up | shipped (W7-01 — 2026-08-19) |
| FR-P18 | T3 | AI-agent / non-human-identity issuance: short-lived, attested, workload-bound | an AI agent/NHI obtains a scoped, expiring, attested identity; issuance is policy- and approval-governed | D-056 | shipped (W7-02 — 2026-08-19) |
| FR-P19 | T3 | SLO-native PKI ops: golden-signal dashboards + issuance/renewal SLOs + error budgets | dashboards show issuance latency, renewal success rate, time-to-expiry distribution; SLO breach alerts fire | D-057 | shipped (W7-03 — 2026-08-19) |
| FR-P20 | T3 | AI-assisted ops: issuance-anomaly detection + natural-language policy authoring | an anomalous issuance pattern raises a finding; a policy can be drafted from NL and lands as a proposed (never auto-active) rule | D-058 | shipped (W7-04 — 2026-08-19) |
| FR-P21 | T1 | Report export in CSV/XLSX (beyond JSON + PDF) | inventory and findings export as CSV/XLSX; column set is documented | PE-11, D-059 | shipped (W7-05 — 2026-08-19) |
| FR-P22 | T2 | Service-mesh + SaaS/API discovery breadth | discovery finds Istio/Linkerd mesh certs and configured SaaS/API endpoints, unified into inventory | D-060 | shipped (W7-06 — 2026-08-19) |
| FR-P23 | T1 | Agent enrollment attestation (close open registration) | agent registration requires an enrollment secret or attestation (TPM/mTLS/SPIFFE); anonymous registration is rejected | PE-7, D-061 | shipped (W5-07 — 2026-08-19) |

## Agentless & fleet management (both modes first-class)

| ID | Tier | Requirement | Acceptance sketch | Traces | Status |
|---|---|---|---|---|---|
| FR-P24 | T1 | User-authored **managed-target** model: declare a target/fleet with per-target `discovery_mode` (agent\|network\|cloud\|none), `install_mode` (agent\|ssh\|f5\|citrix\|cloud\|acme), `renewal_method`, `credential_ref`, and schedule — the fleet is no longer implicit-by-agent-registration | a user can declare a target and its modes via API+UI; renewal/install honor the per-target mode, not global env | D-062 | shipped (W5-09, S-17, W5-13 — 2026-08-18) |
| FR-P25 | T1 | **Outbound credential store** (encrypted at rest): SSH keys, device API creds (F5/Citrix), cloud IAM refs — referenced by targets, never inlined | a credential is stored encrypted, referenced by id from a target, and never returned in plaintext over the API | D-063 | shipped (W5-10 — board done, no STATUS line, <=2026-07-28 baseline) |
| FR-P26 | T1 | **Agentless install via SSH**: the hub pushes a renewed cert+key to a remote target over SSH and runs test→reload→verify→rollback, reusing the agent's install state machine | an SSH-mode target gets a renewed cert installed + verified with no agent on the host; failure rolls back | D-064 | shipped (W5-11, W5-13 — 2026-08-18) |
| FR-P27 | T1 | **Agentless discovery is real & scheduled**: the network scanner persists to the DB (not in-memory), runs on a recurring schedule, and the `cloudinventory` connectors + reserved `scan_jobs.type` values (cloud/ssh/winrm) are wired | a scheduled network+cloud scan populates `endpoints`/`scan_results` durably; cloudinventory is no longer dead code | D-065 | shipped (W5-12 — 2026-08-19) |

## UX, onboarding & in-app configuration

| ID | Tier | Requirement | Acceptance sketch | Traces | Status |
|---|---|---|---|---|---|
| FR-P28 | T1 | A reusable **wizard/stepper** component primitive (none exists today) | a multi-step flow with back/next/validate/summary lands as a shared component with tests | D-066 | shipped (W8-01 — board done, no STATUS line, <=2026-07-28 baseline) |
| FR-P29 | T1 | **Day-0 onboarding wizard**: first-run detection → create root CA → first template → first issuance → choose agent-vs-agentless discovery/install — replacing the dead-end empty dashboard | a fresh install walks an admin from zero to a first issued cert + a configured discovery mode without editing env | D-067 | shipped (W8-02 — board done, no STATUS line, <=2026-07-28 baseline) |
| FR-P30 | T1 | **In-app configuration store + API**: settings the code reads from ~101 env vars become DB-backed and API-readable/writable (env stays the bootstrap default; DB overrides) | a documented set of runtime settings (notification channels, renewal policy, discovery provider, SSO) is editable via API without a server restart | D-068 | shipped (W8-03, W8-13 — 2026-07-30) |
| FR-P31 | T1 | **Integrations/config UI**: notification channels (Slack/PagerDuty/SMTP/webhook), SSO/OIDC, key backends, renewal policy — editable in-app, not env-only | each integration is configurable + testable from Settings; today only evidence-delivery is UI-writable | D-068 | shipped (W8-04 — 2026-07-29) |
| FR-P32 | T1 | **Guided issuance wizard**: CA → template → subject/SANs → key/CSR choice → issue → download/next-action, replacing the single flat dialog | issuance is a validated multi-step flow ending in a download/install step | D-069 | shipped (W8-05 — 2026-07-29) |
| FR-P33 | T1 | **Guided renewal-policy UI**: set auto-renew thresholds + method per target/fleet (today env-only) | a user sets renewal policy in-app; it drives the scheduler (W4-02) per target | D-070 | shipped (W8-07, W8-15 — 2026-07-29) |
| FR-P34 | T1 | **Interactive agent + agentless setup flow**: agent = token-gen + live pairing status; agentless = target + mode + credential in a guided flow (not a static copy-paste snippet) | enrolling an agent shows live pairing; adding an agentless target is a guided form writing the FR-P24 model | D-071 | shipped (W8-06 — 2026-07-28) |
| FR-P35 | T1 | **Role-aware navigation**: nav sections filter by principal role (today static; only action buttons gate) | a viewer does not see admin-only nav; driven by the existing `useAuthz` helpers | D-072 | shipped (W8-08 — 2026-07-28) |
| FR-P36 | T2 | **PQC migration journey UI**: plan → select certs → schedule → execute (wraps the W4-03 execute action) — not a passive report | a CISO drives a migration wave from plan to executed in-app | D-073 | shipped (W8-09 — 2026-08-19) |
| FR-P37 | T2 | **Command-palette actions**: ⌘K can *do* (issue/renew/revoke), not only navigate | a user issues/renews from ⌘K, routed through the same approval/audit path | D-074 | shipped (W8-10 — 2026-07-29) |
| FR-P38 | T1 | **Empty-state CTAs**: every empty state offers the action that fills it (today mostly text-only) | the day-0 empty dashboard has a "Create your first CA" button, etc. | D-075 | shipped (W8-10 — 2026-07-29) |
| FR-P39 | T2 | **Real-time status** via SSE for long ops (scan/renew/install/migrate) instead of 30s polling | a running scan/renewal streams status without a manual refresh | D-076 | shipped (W8-11, W8-14 — 2026-07-30) |
| FR-P40 | T1 | **Bulk actions across inventory pages** (not just Certificates): discovery, keys, agents | multi-select + bulk action on Discovery and Keys, matching the Certificates pattern | D-077 | shipped (W8-11, W8-14 — 2026-07-30) |

## Key management (lifecycle completion + bug fixes)

| ID | Tier | Requirement | Acceptance sketch | Traces | Status |
|---|---|---|---|---|---|
| FR-P41 | T1 | PKCS#11 HSM backend compiles, satisfies the Store interface, is built+tested in CI | `-tags pkcs11` builds; `PublicKey(id)` implemented; `CreatedAt` typed correctly; a SoftHSM2 test signs | D-079, G-32 | shipped (W9-01 — board done, no STATUS line, <=2026-07-28 baseline) |
| FR-P42 | T1 | Cloud KMS (AWS/GCP/Azure) is reachable from the running binary and persists key references | `main.go` constructs the KMS store on config; id→ARN refs survive restart via a DB table | D-080, G-34 | shipped (W9-02 — 2026-08-19) |
| FR-P43 | T1 | PQC/hybrid keys can be exported/escrowed (serialization that accepts ML-DSA) | export+import round-trips an ML-DSA and a hybrid key; a test covers it | D-081, G-31 | shipped (W9-03 — board done, no STATUS line, <=2026-07-28 baseline) |
| FR-P44 | T1 | CA re-key / rotation lifecycle + guard | a CA can be re-keyed and re-issued/cross-signed; bare `RotateKey` on an in-use CA key is refused with guidance | D-082, G-35 | shipped (W9-04 — board done, no STATUS line, <=2026-07-28 baseline) |
| FR-P45 | T1 | Key-generation policy (algorithm allow-list, min-strength, per-CA/role) | a request for a below-floor algorithm (e.g. root CA RSA-2048) is refused with a cited rule | D-083, G-42 | shipped (W9-05 — 2026-08-19) |
| FR-P46 | T2 | M-of-N key ceremony state machine (pending_ceremony → active on quorum) | a root-CA ceremony requires N-of-M approvals before the key is usable; Shamir or multi-approver | D-084, G-41 | shipped (W9-06 — 2026-08-19) |
| FR-P47 | T1 | Secure key destruction: memory zeroization + KMS `ScheduleKeyDeletion` | deleting a key zeroizes cached material and schedules provider deletion; the false RISKS.md claim becomes true | D-085, G-40 | shipped (W9-07 — 2026-08-19) |
| FR-P48 | T2 | HSM/KMS support for ML-DSA/hybrid keys (or documented software-only risk acceptance) | a PQC key is generated + signed in the HSM/KMS, OR an ADR records PQC-keys-are-software-only | D-086 | shipped (W9-08 — 2026-08-19) |
| FR-P49 | T2 | Per-key ACL + rotation schedule/auto-rotate + key-compromise workflow | keys have owners/ACLs beyond global-admin; a max-age auto-rotate runs; a compromise flow force-rotates + re-issues affected certs | D-087 | shipped (W9-09 — 2026-08-19) |
| FR-P50 | T2 | Dual-control / quorum for destructive key ops (delete/rotate/export) | a destructive key op requires a second approver, routed through the approval queue | D-088 | shipped (W9-10 — 2026-08-19) |
| FR-P51 | T2 | FIPS 140-2/3 posture: validated-module build + documented boundary | a FIPS build tag / validated crypto module path exists; NFR-011 (root key HSM/air-gap) is enforced, not just claimed | D-089 | shipped (W9-11 — 2026-08-19) |

## Deployment, release & operability

| ID | Tier | Requirement | Acceptance sketch | Traces | Status |
|---|---|---|---|---|---|
| FR-P52 | T1 | A real versioned migration runner (embed + apply ordered up/down with schema-version tracking) | on startup the hub applies pending migrations transactionally incl. ALTERs; a version table records state; rollback works | D-090, G-33 | shipped (W10-01 — board done, no STATUS line, <=2026-07-28 baseline) |
| FR-P53 | T1 | `/readyz` verifies real dependencies (DB + keystore); k8s readiness probe uses it | `/readyz` returns non-200 when the DB is down; chart readiness probe points at `/readyz` | D-091, G-37 | shipped (W10-02 — board done, no STATUS line, <=2026-07-28 baseline) |
| FR-P54 | T1 | CA-key backup + hub DB backup/restore + DR tooling with an executed drill | scripted `pg_dump`/restore + key backup; a documented, EXECUTED recovery drill | D-092, G-36, S-01 kin | live-proven (2026-07-28) |
| FR-P55 | T1 | Deploy pipeline is wired + verified: fix `smoke.sh` endpoints; `by-digest.sh` targets helm/kubectl | promote/rollback actually deploys; smoke checks the real `/healthz`,`/readyz` | D-093, G-38 | shipped (W10-04 — board done, no STATUS line, <=2026-07-28 baseline) |
| FR-P56 | T1 | Helm chart reconciled with docs + correct image path + external-secrets support | documented values keys match the chart; image registry is consistent; secrets support secretRef/ExternalSecrets, not only inline plaintext | D-094, G-39 | shipped (W10-05 — board done, no STATUS line, <=2026-07-28 baseline) |
| FR-P57 | T2 | Compose is quickstart-true: `.env.example`, override file, sqlite/postgres default fixed, UI build stage | `docker compose up` works from a clean checkout without a manual UI build or missing files | D-095 | shipped (W10-06 — 2026-07-30) |
| FR-P58 | T1 | Agent + MCP + certmanager container images | each binary ships a distroless non-root multi-arch image (extends G-29 beyond MCP) | D-096, G-29 | shipped (W10-07, W10-13 — 2026-07-30) |
| FR-P59 | T2 | Chart HA/observability objects: Postgres guidance/subchart, ServiceMonitor, PDB, NetworkPolicy | `helm install` yields a scrapable, HA-safe deployment; Prometheus scrapes `/metrics` end-to-end | D-097 | shipped (W10-05 — board done, no STATUS line, <=2026-07-28 baseline) |
| FR-P60 | T2 | `/metrics` registered on all serving paths + wired to Prometheus | metrics present regardless of the protocols flag; a ServiceMonitor scrapes it | D-098 | shipped (W1-05 — board done, no STATUS line, <=2026-07-28 baseline) |
| FR-P61 | T2 | Air-gap / offline install bundle (image tarballs + private-registry mirror + offline chart) | a documented offline install works with no external pulls — the regulated/ADCS market | D-099 | shipped (W10-10, W10-15 — 2026-07-30) |
| FR-P62 | T2 | Infrastructure-as-code to stand up kryptkeeper (Terraform: DB + compute + networking) | a Terraform module provisions a runnable environment (distinct from the cert-managing provider) | D-100 | shipped (W10-11 — 2026-07-30) |
| FR-P63 | T2 | Distribution packaging: deb/rpm, Homebrew, published Helm repo, one-command installer; reconcile cosign signing model | a user installs via a package/one-liner; the keyless-vs-keyed signing inconsistency is resolved + key custody documented | D-101 | shipped (W10-12 — 2026-07-30) |

## Estate management — CA-agnostic inventory + takeover (V5, D-106)

The other half of the market: manage certificates *other* CAs issued, with a
path to bring each under management. Basis: `docs/sdlc/phase-0-ideation/VISION_V5.md`;
closes the "direct-CA import" hole inside Tier-1 capability #1 of the competitive brief.

| ID | Tier | Requirement | Acceptance sketch | Traces | Status |
|---|---|---|---|---|---|
| FR-P64 | T1 | **Estate model**: every inventory cert carries `origin` (internal\|imported\|discovered\|synced) and `management_state` (managed\|external\|unmanaged); dashboard + reports split by both | inventory rows persist both fields; the dashboard shows the managed/external/unmanaged split; risk/expiry/PQC reports cover all origins | D-106 | shipped (W11-01, W11-08 — 2026-08-18) |
| FR-P65 | T1 | **Bulk import**: PEM/PKCS#7 bundle, CSV, and API ingest many certs at once with ownership mapping and fingerprint dedupe | a 500-cert bundle imports in one operation; duplicates are skipped by fingerprint with a report; each row lands as origin=imported | D-106 | shipped (W11-02, W11-08 — 2026-08-18) |
| FR-P66 | T1 | **External-issuer connector framework**: an issuer interface the internal CA engine and upstream connectors both satisfy; per-connector config, health, and audit | a template/target can name a connector as its issuer; issuance routes through it; connector failure is a visible health state, not a silent drop | D-106 | shipped (W11-03 — 2026-08-18) |
| FR-P67 | T1 | **ACME upstream connector** (RFC 8555 client incl. EAB): renew/issue *at* Let's Encrypt or any public ACME CA, then run the existing install/verify machinery | an ACME-sourced cert renews through the connector end-to-end (order→challenge→issue→install→verify) with no human step | D-106 | shipped (W11-04 — 2026-08-18) |
| FR-P68 | T2 | **Direct-CA inventory sync**: ADCS sync-in first; a commercial-CA adapter interface (DigiCert/Sectigo/Entrust as adapters) pulling issued-cert inventory read-only | an ADCS environment's issued certs appear as origin=synced with issuer metadata; one commercial adapter demonstrates the interface | D-106 | shipped (W11-05 — 2026-08-18) |
| FR-P69 | T1 | **Takeover flow**: from any unmanaged/external cert — assign owner → choose renewal path (internal CA or upstream connector) → managed; audit-logged, not approval-gated (D-127) | a discovered cert becomes managed in one guided flow; its next renewal executes via the chosen path; the transition is in the audit log | D-106, D-127, NFR-P2 | shipped (W11-06 — 2026-08-18) |
| FR-P70 | T2 | **SSH certificate authority**: issue short-lived SSH certs (user + host) under the same template/approval/audit spine; extends the sshkeys inventory | an SSH cert is issued against a template, honors validity policy, appears in inventory, and is audit-reconstructable | D-106 | shipped (W11-07 — 2026-08-18) |

Scope recorded (D-106): KMIP deferred until customer pull; PGP/OpenPGP out of scope.

## CA choice (1.1, W36)

| ID | Tier | Requirement | Acceptance sketch | Traces | Status |
|---|---|---|---|---|---|
| FR-P93 | T1 | **External CA behind every front door**: a CA row of type external delegates signing to an issuer connector; REST, ACME, EST, SCEP, CMP, WSTEP, cert-manager and Terraform issue through it with hub template policy enforced first | an ACME order against an external CA returns a certificate issued by the upstream; a response whose key, SANs, CA flag or validity differs from the request is rejected and audited | D-304, D-305 | planned (W36-02) |
| FR-P94 | T1 | **Upstream revocation**: revoking a certificate issued through a revoke-capable connector revokes it at the upstream CA first and fails loudly when the upstream refuses | upstream success gives revocation_scope upstream; upstream failure returns 502 and leaves the certificate unrevoked; inventory-only is an explicit admin choice | D-306 | planned (W36-01, W36-03) |
| FR-P95 | T1 | **Upstream CA breadth**: issue and revoke through Vault PKI, EJBCA, AWS Private CA, Google CAS, Sectigo, GlobalSign, Entrust, DigiCert and any ACME CA | each type passes fixture tests pinned to the vendor API; Vault PKI and EJBCA pass live container runs | D-307 | planned (W36-04..W36-11) |
| FR-P96 | T1 | **Issuers UI**: add, test, use and remove upstream CAs without the API, including ACME presets | an operator adds a Vault PKI issuer, tests it and creates an external CA from the wizard; delete is blocked while referenced | D-304 | planned (W36-12..W36-14) |
| FR-P97 | T1 | **External CA tenancy**: an external CA, its connector and its credential share a tenant under multi-tenancy | cross-tenant binding refused at create, update and issue | D-308 | planned (W36-02) |
| FR-P98 | T1 | **Easy adoption**: one-command trial with demo data, and installs from Helm (OCI), Homebrew, apt/yum, the Terraform registries and Ansible Galaxy, each verified after release | a new user reaches a seeded dashboard in five minutes; every channel installs the release in CI | D-309..D-312 | planned (W37) |

## Code-signing lifecycle (UC-B09)

| ID | Tier | Requirement | Acceptance sketch | Traces | Status |
|---|---|---|---|---|---|
| FR-P90 | T1 | **Approval-gated code-signing issuance**: a template whose EKU includes codeSigning always requires approval (regardless of its `require_approval` flag), approver != requester, audited | a code-signing request yields 0 certs and HTTP 202 until a second user approves; approver == requester is refused; audit `certificate.issue` (template codeSigning) and `codesign.request.deny` | D-017, UC-B09 | planned (W26-22) |
| FR-P91 | T1 | **Protected code-signing key generation**: in protected mode the key pair is generated in the HSM/KMS store (PKCS#11, cloud KMS) with CKA_EXTRACTABLE=false and the CSR is built there | the generated private key cannot be exported (export attempt fails; SoftHSM2 test behind the `pkcs11` tag); a software-store hub refuses protected mode | D-079, UC-B09, UC-M03 | planned (W26-22, W26-24) |
| FR-P92 | T1 | **Key attestation for requester-supplied code-signing CSRs**: in protected mode a CSR is accepted only with a vendor attestation (e.g. YubiKey PIV attestation chaining to the vendor root) whose attested public key equals the CSR key; the attestation is stored on the request | valid attestation accepted and stored; missing, forged or mismatched attestation refused | UC-B09 | planned (W26-23) |

Scope recorded (UC-B09): the v1.0 claim covers approval-gated issuance, protected key generation, attestation and the inventory policy check (`/inventory/code-signing*`, FR-P41 for the HSM backend). The code-signing SERVICE with per-use audit (SignServer-style) is carried only by UC-M08 and is NOT claimed by these requirements.

User stories:

- **US-CS1** As a publisher (Jordan) I request a code-signing certificate and receive it only after a second person approves, so that no single person can mint a signing identity. AC: maps to FR-P90.
- **US-CS2** As a security owner I require the signing key to be generated inside the HSM/KMS and never exported, so that a compromised build host cannot steal it. AC: maps to FR-P91.
- **US-CS3** As a publisher with a hardware token I submit my own CSR with the token's attestation, so that the hub can prove the key lives in hardware. AC: maps to FR-P92.

## Non-functional / positioning

| ID | Requirement | Basis |
|---|---|---|
| NFR-P1 | Every product claim in GO_FORWARD_PLAN maps to a shipped capability or is scoped honestly (fix the 5 over-claims) | PRODUCT_ENHANCEMENTS positioning table |
| NFR-P2 | New action surfaces (renew/rotate/migrate/CT-finding) inherit the approval-gate + audit + tenant-scope invariants | D-017, D-022, R-B* |
| NFR-P3 | The IA/design docs are refreshed to the current 29-page product (UX_SPEC covers only the original 7); persona set aligned (5 in USER_PERSONAS vs 4 in UX_IMPROVEMENT_PLAN); wizard + config-IA + journey maps documented | UX map §6 |
| NFR-P4 | Every board ticket has a decision-complete spec in `docs/board/specs/<id>.md` before it is claimed, so a cheap model can execute it without design decisions | kickoff §2.1 |
