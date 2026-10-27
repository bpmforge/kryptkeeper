# Changelog

All notable changes to Kryptkeeper are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Kryptkeeper adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

## [1.1.0] - 2026-10-27

Release notes: [docs/release/RELEASE_NOTES_v1.1.0.md](docs/release/RELEASE_NOTES_v1.1.0.md).

### Added

- External CAs behind every protocol (Vault PKI, EJBCA, AWS Private CA, Google CAS, Sectigo, GlobalSign, Entrust, DigiCert, any ACME CA), verified responses and upstream-first revocation; Issuers page and wizard (W36).
- Five-minute trial with demo data, signed OCI Helm chart, post-release verification, Ansible collection (W37).
- Plugin kinds (notify, ticket, dns01, credentials) with Teams, PagerDuty, Opsgenie, Zendesk, Freshservice, DigitalOcean, GoDaddy, NS1, Akamai, CyberArk and Delinea plugins; signed plugin catalogue; Vault/OpenBao credential sources; owner routing, durable retries, ITSM ticket on failed renewal; cloud certificates in inventory; scheduled reports; Intune SCEP (W38).
- SQL Server, RDP and Exchange install modes, domain-account installs, NLA RDP discovery, persisted CA rate-limit hold and rolling issuance budget (W39).
- PQC delivery to HAProxy and Kubernetes, ACME device attestation, trust store push (W40).

### Changed

- Notification retries: 8 attempts with exponential backoff (were 3).
- Go toolchain 1.27.3.

### Fixed

- PQC wave verification of ML-DSA deliveries: Go 1.26's TLS client offers no ML-DSA signature scheme, so the build uses Go 1.27.3 (go.mod and all Dockerfiles). The FIPS build keeps the `GOFIPS140=v1.0.0` module (CMVP #5247).
- The hub container image ships `/var/kryptkeeper/{data,keys,tls-trust}` owned by the nonroot user. On Docker Engine a fresh named volume was created root-owned, so the hub could not create its database and restarted in a loop (`mkdir /var/kryptkeeper/data: permission denied`). Podman masked it by chowning new volumes.
- Issued leaves no longer carry `keyEncipherment` on EC or ML-DSA keys, or on code-signing, time-stamping and OCSP-signing certificates (RFC 5280, RFC 8813). Time-stamping EKU is now critical (RFC 3161) and OCSP-signing certificates carry `id-pkix-ocsp-nocheck` (RFC 6960). Found by the new pkilint/zlint profile check in CI.
- The nightly perf benchmark runs the hub with the documented `GOMEMLIMIT=1600MiB` and takes issue throughput as the median of three passes; the bars are unchanged.
- LICENSE is the verbatim Apache License 2.0 text.
- External-CA failures answer with their reason instead of a bare 503.
- Plugin http events no longer log full URLs (webhook signatures).

### Deprecated

- The Opsgenie notify plugin (D-329). Atlassian ends Opsgenie support on 2027-04-05. The hub warns when the plugin is installed or loaded; it is removed in 2.0.

## [1.0.0] - 2026-10-18

Release notes: [docs/release/RELEASE_NOTES_v1.0.0.md](docs/release/RELEASE_NOTES_v1.0.0.md).
Lab record: [docs/release/LIVE_RESULTS_v1.0.0.md](docs/release/LIVE_RESULTS_v1.0.0.md).

### Added

- Discovery fingerprinting, certificate classification and install-posture findings (W34).
- Privileged agentless Linux scans through one privilege layer (none, nopasswd, password, helper) (W34).
- WSTEP/XCEP enforce every template enroll list, with a one-time upgrade (D-291).
- Approver role decides certificate requests on templates that name it.
- Readiness drain on shutdown (`KRYPTKEEPER_READINESS_DRAIN_SECONDS`) and prompt lease hand-back.

### Fixed

- GPO autoenrollment refused since 0.10 (XCEP key size and algorithm families).
- Agentless WinRM discovery and IIS installs (argument encoding).
- Postgres connection exhaustion; fail-closed agent, break-glass and access-review stores (D-290).
- SQLite refresh/write deadlock; takeover reverted by a stale refresh.
- Key operations 403 + DB detail leak when the policy store is down (now 503).
- Windows agent `LocalMachine\My` inventory; Linux agent keystore and kubeconfig discovery.
- ADCS migration update/rollback safety and CA-infrastructure template filtering.
- About 25 UI issues from the screenshot tour.

## [0.21.0] - 2026-10-17

Release notes: [docs/release/RELEASE_NOTES_v0.21.0.md](docs/release/RELEASE_NOTES_v0.21.0.md).

### Added

- **Adoption UX (W33-01..34).** Playwright harness and journeys, per-user
  onboarding dismissal, SAML/SCIM/key-backend config with source badges, SSO
  override lock-out guard, team policies with quotas, Requester role and My
  Requests, on-behalf-of requests, tenant-scoped single-use agent enrollment,
  jsx-a11y and an axe sweep in CI, an ACR/VPAT, migration playbooks, a
  responsive navigation drawer, and a Keycloak harness. Migrations 000320 to
  000324.
- **v1 UI/UX review** across estate, ops, admin and report pages.
- **v1 security scan** (`docs/security/V1_SCAN_2026-10-17.md`): tenant gates fail
  closed (D-202), agent/NHI/SPIFFE admin APIs are global-admin-only under
  multi-tenancy (D-203), SCIM grant ceiling and `SCIM_ALLOW_ADMIN_ROLES`
  (D-204), egress-guarded F5/Citrix/K8s and OIDC clients.

### Changed

- Unmounted `/api/` paths answer 404 JSON instead of the 200 text banner.
- **A fresh hub can start with zero CAs (W33-32).** With no CA,
  `KRYPTKEEPER_DEFAULT_CA_ID` unset and `KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT` off,
  the hub now logs `[FIRST-RUN]` and starts so the onboarding wizard can create
  the first root, instead of exiting with `no CA configured`. ACME, EST, CMP and
  WSTEP resolve the default CA per request (the first stored CA) and answer 503
  `no CA configured yet; create a root CA` until one exists; the wizard's root
  becomes the default with no restart. The listener serves an ephemeral self-signed certificate with a
  warning while no CA can self-issue its certificate; SCEP and XCEP need a
  restart after the root exists. A `ListCAs` error or an explicit
  `KRYPTKEEPER_DEFAULT_CA_ID` behave as before.

### Fixed

- A delegate could vote twice on a 2-of-N approval; code-signing inventory
  listed every tenant's certificates; `/reports/change-audit` had no
  `audit.read` check; SAML ACS accepted up to 10 MB before signature checks.

## [0.20.0] - 2026-10-17

Release notes: [docs/release/RELEASE_NOTES_v0.20.0.md](docs/release/RELEASE_NOTES_v0.20.0.md).

### Added

- **Ecosystem (W32-01..33).** OpenAPI spec served at `/api/v1/openapi.yaml`,
  Go/TypeScript/Python SDK generation, Terraform provider tests and data sources,
  plugin registry page, HMAC-signed webhooks with rotation, ITSM framework with
  ServiceNow and Jira connectors, approval-via-ticket, CMDB ownership sync,
  acting-channel audit on approvals, Slack and Teams interactive approvals.
  Migrations 000300 to 000302.

### Changed

- Approval audit rows lead with `channel` and `external_id` (D-186). Webhooks
  are unsigned with a WARN when no secret is set (D-183).

### Fixed

- The `itsm` channel could not be created in notification rules, so ITSM
  producers never fired (W32-33).

## [0.19.0] - 2026-10-17

Release notes: [docs/release/RELEASE_NOTES_v0.19.0.md](docs/release/RELEASE_NOTES_v0.19.0.md).

### Added

- **PQC agility (W31-01..21).** PQC readiness corpus and label fixtures,
  ML-DSA signed CRL and OCSP (`internal/revsign`), FIPS/allow-list/HSM refusals
  (422), PQC migration waves with verify, rollback and approval expiry
  (`KRYPTKEEPER_PQC_WAVE_APPROVAL_TTL_HOURS`), non-PQC algorithm transitions
  through waves, a Crypto Agility roadmap, a Blast Radius page and
  `GET /api/v1/blast-radius`, and a software-only PQC key-custody statement. No
  migrations.

### Changed

- Readiness labels degrade rather than flatter (D-173); wave progress counts
  delivery, not issuance (D-194).

### Fixed

- A PQC wave no longer reports 4 of 4 migrated when members were undelivered
  (W31-21).

## [0.18.0] - 2026-10-17

Release notes: [docs/release/RELEASE_NOTES_v0.18.0.md](docs/release/RELEASE_NOTES_v0.18.0.md).

### Added

- **SRE and operations (W30-01..27).** Percent-of-lifetime expiry thresholds,
  owner-team notification routing, runtime-reloadable channels, SLO error
  budgets and burn rates with Grafana panels, propose-only anomaly remediation,
  natural-language policy drafting (`/policies/draft`), health and metrics
  endpoints for every process with an optional `/metrics` bearer, SSE operation
  events, HA failover audit and alert, reference architectures and the egress
  list. Migrations 000260 and 000261.

### Changed

- Logging is structured JSON (slog) with secret redaction; the std `log` package
  is banned outside tests (D-162). `FanOutChannel.Send` returns
  `ErrNoConfiguredChannel` when nothing is configured (D-169).

### Fixed

- Certificate list/search tail latency and hub peak RSS at 100k certificates
  (search p99 975 to 115 ms, RSS 2.49 to 1.70 GiB, D-170).

## [0.17.0] - 2026-10-17

Release notes: [docs/release/RELEASE_NOTES_v0.17.0.md](docs/release/RELEASE_NOTES_v0.17.0.md).

### Added

- **Machine identity (W29-01..15).** SPIFFE Workload API conformance harness,
  NHI revocation at the authorisation layer within 60 s, NHI management page,
  per-agent single-use enrollment tokens, live MCP client E2E with a
  `blast_radius` tool and tool-catalogue page, code-signing certificates from a
  verified CI OIDC token with `jti` replay protection, an RFC 3161 time-stamp
  service, and a cosign signing guide. Migrations 000240 and 000241.

### Changed

- The shared CSV agent enrollment secret is a warned transition path; per-agent
  tokens are preferred (D-151). The TSA is closed to anonymous callers unless
  `KRYPTKEEPER_TSA_ALLOW_ANONYMOUS=true` (D-153).

## [0.16.0] - 2026-10-17

Release notes: [docs/release/RELEASE_NOTES_v0.16.0.md](docs/release/RELEASE_NOTES_v0.16.0.md).

### Added

- **Compliance reporting (W28-01..21).** Published risk-score formula with a
  doc-versus-code test, crypto posture range picker and compare-two-dates view,
  posture snapshots with a 400-day retention floor, scheduled CSV/XLSX/PDF report
  delivery with retry, CSV formula-injection escaping, FedRAMP Moderate control
  mappings, a control-to-artifact index and key-custody section in every
  evidence pack, manual attestations, CycloneDX 1.6 validated CBOM, tenant-scoped
  key-custody entries and drill-through links on the posture pages. Migrations
  000220 and 000221.

### Changed

- Evidence-pack mail retries 3 times and raises `evidence.delivery_failed`
  (D-140). Posture trend stays super-admin only.

## [0.15.0] - 2026-10-16

Release notes: [docs/release/RELEASE_NOTES_v0.15.0.md](docs/release/RELEASE_NOTES_v0.15.0.md).

### Added

- **Renewal and delivery (W27-01..38).** Explicit cert-to-target bindings with
  a one-time backfill, fleet target groups, a durable renewal failure queue
  with `POST /renewal/retry` and configurable backoff, per-connector throttle,
  worker pool, jitter and shutdown drain, ACME dns-01 (Route53, Azure DNS, GCP
  DNS, RFC 2136, CNAME delegation) and fleet http-01, a DCV tracker,
  DigiCert, SCEP, EST and WSTEP connector types, a Tomcat keystore installer
  (keystore-go v4.5.0), staged install and cluster-atomic rollout groups,
  delivery plugins (vault, azure-keyvault, gcp-secretmanager, aws,
  aws-secretsmanager, azure, cloudflare) with store read-back verification and
  `verify_propagation_seconds`, bulk takeover suggestions, and the matching UI
  (Rollout Groups, DCV panel, Automation queue, target wizard bindings,
  Renewal Policy groups). Migrations 000200-000203 and 000205. Decisions D-127
  and D-128 and the agent upgrade runbook. Dev dependency axe-core 4.10.3 (already on main from v0.14).

### Changed

- A host match without a binding is no longer auto-renewed (existing matches
  are backfilled once). DigiCert, EST and WSTEP refuse plain http. Bulk
  takeover is capped at 500 and validated as a whole. `renewal/execute`
  returns 403 for forbidden certificates, 429 with `Retry-After` for rate
  limits and 409 with `successor_fingerprint`; `install_detail` is capped at
  1 KB. See the release notes' upgrade section.

### Fixed

- ACME finalize works against a CA that omits the order `Location` header.
- The EST client request body ends with a newline (libest returned 400).
- `renewal/execute` returned 503 instead of 403 for team- and tenant-forbidden
  certificates.

## [0.14.0] - 2026-10-16

Release notes: [docs/release/RELEASE_NOTES_v0.14.0.md](docs/release/RELEASE_NOTES_v0.14.0.md).

### Added

- **Enrollment (W26-01..32).** API and UI management for ACME EAB keys and
  provisioners, EST users and label routes, CMP credentials and SCEP
  challenges; ACME server ARI; ACME upstream ARI timing, Retry-After backoff
  and mass-revocation reaction; CMP rr, certConf and pollReq; SCEP renewal;
  approval-gated SSH issuance; code-signing approval, protected keys and
  YubiKey attestation; Terraform provider acceptance tests.

### Changed

- EST answers 401 for unauthenticated clients; repeat issuance of the same key
  returns the existing certificate (200); approval templates check policy
  before queueing; the cert-manager issuer chart renames
  `pollIntervalSeconds` to `resyncIntervalSeconds` and approves its own
  requests. See the release notes' upgrade section.

### Fixed

- The cert-manager issuer could not issue on a real cluster.
- The Baseline policy and the policy API refused RSA-3072.
- WCAG AA contrast in the light theme and wizard heading order.

## [0.13.0] - 2026-10-16

Release notes: [docs/release/RELEASE_NOTES_v0.13.0.md](docs/release/RELEASE_NOTES_v0.13.0.md).

### Added

- **Deploy and distribution (W25-01..21).** Prebuilt dashboard image for
  compose and Helm, Helm HA defaults (2 replicas, PDB, sqlite single-replica
  guard), `kryptkeeper migrate status|down`, SQLite backup and restore,
  air-gap bundle v2 with a signed manifest, signed apt/yum repository
  tooling, two-arch Homebrew formula and signed `install.sh`, licence and
  Terraform CI gates, and the licensing and support policy.

### Changed

- Helm defaults to 2 replicas; Postgres pools are capped per store and
  tunable; the hub refuses to start on a newer schema. See the release
  notes' upgrade section.

### Fixed

- Hub replicas did not see certificates their peers issued, renewed or
  revoked until restart.
- Two replicas exhausted Postgres's default connection limit.

## [0.12.0] - 2026-10-16

Release notes: [docs/release/RELEASE_NOTES_v0.12.0.md](docs/release/RELEASE_NOTES_v0.12.0.md).

### Added

- **Discovery and inventory (W24-01..44).** Per-target scan schedules,
  agentless SSH discovery with host-key pinning, scan-diff and agent change
  alerts, LDAP StartTLS and RDP probes, JCEKS keystores, actionable CT
  findings with a second CT source, multi-account cloud and multi-cluster
  Kubernetes discovery, bulk takeover and revert, estate board report, SSH
  keys and PQC readiness in key inventory, template migration from ADCS,
  Vault, Venafi, Keyfactor and CertCentral with undo, and the matching UI.

### Changed

- Never-run targets scan on the first tick; agent default poll is 60s; the CT
  monitor is always constructed and de-duplicates by serial. See the release
  notes' upgrade section.

### Fixed

- GCP CAS and DigiCert credentials stored as JSON strings were sent quoted.

## [0.11.0] - 2026-10-16

Release notes: [docs/release/RELEASE_NOTES_v0.11.0.md](docs/release/RELEASE_NOTES_v0.11.0.md).

### Added

- **CA and key core (W23-01..54).** 9-algorithm CA matrix (Ed25519, RSA-3072
  added), external root import and offline-root CSR flow, per-CA key
  backends, dual-controlled re-key and cross-sign rollover with rollback, CA
  revocation, key compromise with re-issue, template enrollment permissions
  and revision history, DB-backed CRL numbers, delta CRLs, CRL shards, HA
  readiness gating, FIPS image variant, and the matching UI.

### Changed

- `POST /cas` answers 400 for an unsupported algorithm; CA re-key, CA revoke
  and key compromise are dual-controlled; `DELETE /cas/{id}` removes only
  revoked or expired CAs. See the release notes' upgrade section.

### Fixed

- OCSP GET with `/` in the base64 request, ML-DSA CA KeyUsage bits, missing
  AKI on cross-sign bridges, four Vault transit defects, and CA revoke on
  Postgres.

## [0.10.0] - 2026-10-16

Release notes: [docs/release/RELEASE_NOTES_v0.10.0.md](docs/release/RELEASE_NOTES_v0.10.0.md).

### Security

- **Tenant isolation is enforced (v0.10).** The 21 cross-tenant leaks from the
  v0.9.3 live validation (`docs/release/TENANT_ISOLATION_VALIDATION_v0.9.3.md`,
  L-01..L-21) are closed: API key mint/list/delete, keystore and key grants,
  approved pending actions, bulk revoke, sub-CA parents, global config,
  credentials, notification rules and silences, discovery, audit (stamped from
  the principal, never `X-Tenant`), search, CBOM, SSH certificates,
  connectors, inventory sources, users (now carry a tenant), custom roles
  (now carry `tenant_id`), list totals and the certificate summary
  (W21-01..03, W22-01). The tenant-idor suite reports 0 leaks on both engines.
- **The multi-tenancy experimental start-up gate is lifted** (W22-03, owner
  decision 2026-10-16, `docs/release/MULTI_TENANCY_GATE_DECISION.md`).
  `KRYPTKEEPER_MULTI_TENANCY_GATE=enforce` restores the v0.9 refusal.

### Added

- `GET /api/v1/auth/role-map/preview?groups=a,b` shows the role a set of groups
  would receive (admin only).
- **Issuance policy admin API** (`/api/v1/policies`: CRUD, `dry-run`, audited
  as `policy.create|update|delete`; refusals leave `policy.violation`).
  Instance-global: pki-admin, and the platform super-admin when multi-tenancy
  is on. ACME finalize now returns 400 `badCSR` and EST enroll 403, each citing
  the policy and rule, instead of an opaque 500.

- **Audit:** `kryptkeeper-audit-verify` offline verifier for audit records and
  checkpoints (W22-04; the transparency signing seed is auto-provisioned);
  streamed `GET /api/v1/audit/export?format=csv|json`, tenant-scoped (W22-05);
  retention archive `POST /api/v1/audit/archive` under dual control, writing a
  signed, hash-chained archive before rows are deleted (W22-07).
- **Approvals:** auto-reject after `APPROVAL_TTL_HOURS` (default 72) (W22-09);
  n-of-m quorum per action type via `APPROVAL_QUORUM_POLICY` (W22-10);
  dated approver delegation, max 30 days (W22-11); unified approvals inbox API
  and `/inbox` page replacing the two approval pages (W22-12, W22-13).
- **Policy governance:** loosening an issuance policy needs a second approver,
  tightening applies at once; version history and revert (W22-15); Policies
  page with dry-run, issue wizard cites the violated rule (W22-16).
- **Roles UI** with permission builder, SoD checks and SSO role-map preview
  (W22-18).
- **Ownership:** `ownership_source`, `?owner=unassigned` and a dashboard
  unowned count (W22-24); CMDB ownership import (W22-25); orphaned-owner
  detection and bulk reassignment (W22-26, W22-27).
- **Risk exceptions:** `/api/v1/exceptions` behind the approval queue, tenant
  scoped, with expiry warning and auto-reopen (W22-28, W22-31); accept-risk on
  Discovery and Crypto Posture and the five-stage finding funnel (W22-29,
  W22-30); accepted risks in compliance evidence packs (W22-32).
- **Access governance:** API key `last_used_at` (W22-33); access review report
  and recertification campaigns with a signed close (W22-34..36); break-glass
  accounts with two-person activation, 4 h windows, alerting, review tasks,
  IdP-down local login and quorum override (W22-37, W22-38).
- **Protocol hardening:** per-credential protocol rate limits (W22-39); egress
  lint for user-URL HTTP clients (W22-40); `docs/security/SECURITY_CLAIMS.md`
  (W22-41).
- **Tests:** `--suite tenant-idor` replays every OpenAPI route as four roles
  of one tenant against another tenant's data, on SQLite and PostgreSQL
  (W22-02); Keycloak OIDC/SAML/SCIM live harness (W22-21, W22-22).

### Changed

- **A baseline issuance policy is now enabled whenever the policy table is
  empty** (fresh AND upgraded installs that never defined a policy): RSA
  keys over 2048 need >= 3072 bits (RSA-2048 is not on the allow-list),
  validity <= 398 days, no CA certificates through the leaf path. Existing
  policies are never overridden. To opt out, delete or disable `pol-baseline`.

- **BREAKING: an SSO user whose IdP groups map to no role is now denied.**
  Previously an unmapped identity silently became a read-only `viewer`. OIDC
  and SAML browser login now answer 403 for a provisioned user with no mapped
  group and no role on the account; `AUTH_MODE=jwt|oidc` bearer tokens with no
  mapping are refused (401). Set `APP_AUTH_UNMAPPED_ROLE=read-only` to restore
  the old viewer fallback explicitly. `APP_SCIM_DEFAULT_ROLE` no longer
  defaults to `pki-viewer`: a SCIM user with no group has no role until a group
  maps one.
- OIDC/SAML login applies `APP_AUTH_ROLE_CLAIM` + `APP_AUTH_ROLE_MAP_JSON` to
  the IdP group claim and persists the mapped role on the user record.
- Refresh tokens now expire after `APP_AUTH_IDLE_TIMEOUT_SEC` (default 1800)
  without use.

### Fixed

- Migration 000090 drops the legacy `users.role` CHECK, which rejected
  `viewer`, `auditor`, `approver`, custom roles and the empty role.

## [0.9.4] - 2026-10-15

### Added

- **Releases now ship the Windows agent.** `kryptkeeper-agent_<version>_windows_amd64.zip`
  and a `.msi` (built with `wixl` from a goreleaser post-build hook, so it
  embeds the zip's exe) are attached to each release and listed in the
  cosign-signed `checksums.txt`. See `packaging/README.md`.
- **Homebrew formula as a release asset.** Each release attaches
  `kryptkeeper.rb` (darwin/arm64 tarball URL + signed sha256; Intel Macs are
  unsupported) with a keyless cosign signature. `make release-snapshot` builds
  the whole release set locally.
- **macOS agent as a LaunchDaemon.** `packaging/macos/com.kryptkeeper.agent.plist`
  and `docs/ops/MACOS_AGENT.md` (launchctl bootstrap/bootout, enrollment, logs).
  Validated live on macOS with the v0.9.4-rc.2 assets.
- **Windows agent docs: HTTP-01 needs inbound TCP 80.** `docs/ops/WINDOWS_AGENT.md`
  gives the scoped firewall rule, the IIS/port-80 conflict guidance and the
  v0.9 no-install limit.

- **ACME dns-01 propagation check is configurable.** New connector
  `config_json` fields `dns_propagation` (`auto` default, `authoritative`,
  `resolver`, `doh`, `none`), `dns_resolver`, `dns_doh_url`,
  `dns_propagation_timeout` (default 3m, max 10m) and
  `dns_propagation_delay`. `auto` keeps the authoritative check and falls
  back to DNS-over-HTTPS, then the resolver, when no nameserver answers
  (outbound port 53 blocked). See `docs/ops/ACME_UPSTREAM.md`.

### Fixed

- **Agent ACME renewal detects a busy :80 on Windows.** The pre-check bound
  only dual-stack `tcp :80`, which succeeds beside an IPv4-only listener on
  `0.0.0.0:80`, so renewal failed later with an opaque ACME error. IPv4 and IPv6
  are now probed separately (an unsupported family is skipped) and the challenge
  server listens on both.
- **ACME authorization failures say why.** The Hub never recorded a reason on a
  failed http-01/dns-01 challenge, so clients printed `authorization error for X: `
  with nothing after the colon. The challenge `error` problem now carries the
  fetch/lookup failure (e.g. the URL and status or connection error), and the
  agent adds a hint when a CA still gives no detail.
- **Homebrew packaging was broken.** The formula template expected raw
  `kryptkeeper-darwin-*` binaries that the goreleaser release never published
  and the `homebrew-formula` job had been removed; it now renders from the
  signed `checksums.txt` against the real tarball. `packaging/README.md` no
  longer describes a tap-less `brew install ./kryptkeeper.rb` (Homebrew 7
  needs a tap; local-tap steps documented).
- **Agent re-dispatched a pending renew task on every poll.** A second ACME
  order raced the first for port 80 ("Only one usage of each socket
  address"). Renewals now run one at a time, a failing one backs off 1m to 1h
  with jitter, and failures are reported to the hub with the error.
- **Agent HTTP-01 failed opaquely when port 80 was unavailable.** It now checks
  the port before ordering and says "port 80 in use or not permitted".
- **Windows agent tried `sudo` installs.** Tasks with install hints are
  refused up front with a reported error; use agentless WinRM/IIS in v0.9.
- **ACME dns-01 renewals failed on networks that block outbound port 53.**
  The record was only looked for at the zone's authoritative nameservers,
  so it was never seen and the renewal failed with "not visible at <ns>
  before the deadline". `auto` now falls back to DoH or the resolver.
- **`POST /api/v1/renewal/execute` returned an empty reply on a slow
  renewal.** Its 180s write deadline was not longer than the dns-01 wait.
  The deadline now covers the maximum propagation wait plus order and
  install time, and the error or result is always written as JSON.

## [0.9.3] - 2026-10-15

### Behaviour changes

- **Discovery now defaults to the `db` provider.** The code default (unset),
  `env.example`, `docker-compose.yml` and the Helm chart used `file` or
  `scanner`, which are stubs: `scanner` is in-memory, scans port 443 only, ignores
  `scan_type` and custom ports, persists no certificates and shows no flags or
  posture. Compose users upgrading switch from that to persisted discovery: the
  inventory now survives restarts and scans use the catalogue port list for their
  scan type. An unknown value now falls back to `db` (it fell back to `file`).
  `APP_DISCOVERY_PROVIDER=scanner` and `file` stay selectable; set
  `APP_DISCOVERY_PROVIDER=file` explicitly if you relied on the unset behaviour.

### Added

- **Discovery says whose certificate it is.** Every TLS-served chain is now
  verified (a real `x509` Verify of the leaf with the served intermediates)
  against the system roots and this hub's own CAs, and each discovered leaf gets
  a `trust_class`: `managed` (chains to a hub CA), `public` (chains to a system
  root), `private_other` (some other CA), `self_signed`, or `unknown`.
  `chain_complete` / `chain_trusted` are now populated, and new risk flags
  `INCOMPLETE_CHAIN` (the server did not send enough to reach an anchor) and
  `UNTRUSTED_ROOT` (the served chain ends in a root nobody here trusts) are
  raised (see Fixed for the final `INCOMPLETE_CHAIN` rule). An expired certificate is still attributed to its issuer; expiry is
  flagged separately. Intermediates and roots a server presents are stored as
  chain CAs (migration `000077`: `trust_class`, `is_ca`) and kept out of the leaf
  inventory, the Unmanaged filter and the dashboard counts. The trust class is
  on certificates, discovery endpoints (with a `trust_class` filter on
  `/certificates` and `/discovery/endpoints`) and both summaries; the Dashboard
  shows a "Seen on the network by issuer" breakdown whose segments open the filtered
  inventory, and the Certificates and Discovery pages filter by it. There is no
  AIA fetching, so a leaf served alone under an intermediate no pool holds reads
  `private_other` with unknown chain completeness.

- **Discovery detects servers that only speak TLS 1.0, TLS 1.1 or SSLv3.** The
  scanner's Go client cannot handshake below TLS 1.2 by default, so such a server
  looked like a generic failure. When the normal handshake fails on an open
  port, the scanner retries once with `MinVersion` lowered to TLS 1.0 (capture
  only; normal verification is untouched, and a modern server never sees the
  retry) and, failing that, sends a minimal ClientHello capped at TLS 1.1 and
  reads the ServerHello version without completing a handshake. The endpoint is
  recorded with `DEPRECATED_TLS_VERSION: TLSv1.0` (or `TLSv1.1`, `SSLv3`) and
  counts as risky; its certificate is captured when the Go handshake could
  complete. A server whose only suites are ones Go will not offer (RC4,
  3DES-only) is found by the raw probe and has no certificate. There is no
  policy flagging TLS 1.2 without 1.3, so none is added.

### Changed

- **A certificate served under a name it does not vouch for makes that endpoint
  risky.** `HOSTNAME_MISMATCH` joins `EXPIRED`, `SELF_SIGNED`, `WEAK_KEY`,
  `WEAK_SIGNATURE` and `UNTRUSTED_ROOT` in the risky-endpoint rule (summary
  count, `risky_only` filter and the per-endpoint `risky` field), and a link's
  mismatch also adds its 20 points to that endpoint's score. It applies only to
  the endpoint where the name does not match. `INCOMPLETE_CHAIN` stays a
  finding but is not risky on its own.

### Fixed

- **Certificate chain verdicts no longer contradict the endpoint view.**
  `chain_complete` / `chain_trusted` are omitted from the certificate API (list,
  detail, CSV export blank) for discovered certificates: completeness is a fact
  about each endpoint (`mapped_certs[]` on `/discovery/endpoints`), and the
  certificate-row column was a stale default. Hub-issued/imported certs keep the
  value from issuance, now labelled "as issued" in the UI detail panel.
- **A failed TLS handshake on an open port is a finding like NOT_TLS.**
  `TLS_HANDSHAKE_FAILED` is now risky, and any endpoint with a high-severity
  endpoint finding scores at least 20 instead of 0. A Postgres server that
  answers the SSLRequest with `N` is reported as `POSTGRES_TLS_DISABLED`
  (risky, plaintext database) rather than a generic handshake failure.
- **UI:** the certificate inventory table scrolls inside its card instead of
  clipping Risk/Estate at 1440px; the Discovery endpoint list shows the trust
  class, the top two findings (+N) and a risky marker, and the observed protocol
  ("not TLS") instead of the scan's intended one; the dashboard PQC readiness
  card lists the parts of its percentage (quantum-safe, leaf-only PQC,
  migration-ready, vulnerable) and the expiry-cliff line no longer calls
  already-expired certificates "expiring".

- **`INCOMPLETE_CHAIN` was noise.** Every private-CA leaf was flagged for not
  serving its root (omitting the root is normal), including correctly
  configured leaf+intermediate servers, and so was publicly trusted
  `example.com`. It now fires only when an intermediate is provably missing: the
  chain verifies only through a CA certificate the server did not send (a hub
  intermediate, or one the platform verifier supplied), or a lone leaf names a
  hub intermediate by AuthorityKeyId. A private chain whose issuing CA the hub
  does not hold cannot be judged; `chain_complete` is then unknown (omitted/NULL),
  never `false`, and nothing is flagged. A leaf served alone under a public
  intermediate no pool holds also reads unknown (no AIA fetching).
- **Endpoint-specific facts no longer live on the shared certificate row.**
  `HOSTNAME_MISMATCH`, `INCOMPLETE_CHAIN`, `UNTRUSTED_ROOT` and
  `chain_complete`/`chain_trusted` were stored on `certificates`, so the same
  certificate served on two hostnames flipped with whichever endpoint was
  scanned last (the earlier IP-sweep merge was a stopgap, now removed). They are
  stored on the `certificate_endpoints` link (migration `000079`:
  `endpoint_flags`, `endpoint_risk_score`, `chain_complete`, `chain_trusted`)
  and each endpoint's `mapped_certs` entry carries its own flags, score and
  `chain_complete`. The certificate row keeps only intrinsic flags (`EXPIRED`,
  `WEAK_KEY`, `WEAK_SIGNATURE`, `SELF_SIGNED`, `PQC_VULNERABLE`, `trust_class`);
  its own `chain_complete` is no longer maintained for discovered certs. The
  risky rule and the findings funnel evaluate endpoint flags per endpoint. Links
  written before the migration start empty and fill in on the next scan of each
  endpoint.
- **Hub-issued certificates found on the network are classed `managed`.** A
  mapped cert's `trust_class` is always the effective class (it was empty for
  managed certs), and the dashboard breakdown, now labelled "Seen on the network
  by issuer", counts distinct certificates with an active endpoint mapping by
  class, managed ones included (it showed 0 managed while a managed cert was
  served on two endpoints). The classes sum to `mapped_certificates`, and each
  segment opens the matching endpoints.
- CI: race-enabled unit tests (`unit-backend`, `release-candidate`, `make
  test-race`) run with `-timeout 30m`; `internal/bootstrap` under `-race` takes
  about ten minutes, the default test timeout.

- **Hosts that answer but are not usable TLS no longer vanish from a scan.** A
  plain-HTTP host or a TLS 1.0-only host in a `/27` sweep was dropped from the
  inventory while the job reported `completed`. An open port that is not TLS is
  now recorded with a `NOT_TLS` finding, one whose handshake fails with
  `TLS_HANDSHAKE_FAILED: <error>`; closed or filtered ports are still not
  recorded, so a range scan does not flood the inventory. A scan that reached
  such hosts finishes `completed_with_errors` (new status, migration `000078`)
  and `GET /discovery/scan-jobs` returns an `error` string saying which hosts
  and how many ports were closed; the Discovery page shows it. A failed
  targeted job named an arbitrary catalogue port (5986, 465) because it took
  whichever probe errored first; it now names the host and port deterministically,
  443 first. Nothing reachable still reads `failed`.
- **The "Risky" count, the "Risky only" filter and the dashboard now agree and
  catch what matters.** Risky meant `risk_score >= 70`, so expired,
  self-signed, weak-key and weak-signature certificates scored 40-60 were
  hidden. An endpoint is now risky if a currently-active certificate scores 70
  or more or carries `EXPIRED`, `SELF_SIGNED`, `WEAK_KEY`, `WEAK_SIGNATURE` or
  `UNTRUSTED_ROOT`, or if the endpoint has a `NOT_TLS` or
  `DEPRECATED_TLS_VERSION` finding. `risky_endpoints`, the filter and a new
  `risky` field on each endpoint share that one rule. The Findings widget
  stayed at 0 because it counted only cipheraudit issues; it now also counts
  each current certificate's finding flags (expiry, self-signed, weak key or
  signature, hostname mismatch, incomplete chain, untrusted root; the
  informational `PQC_VULNERABLE` is not counted), per endpoint like the existing
  issues.

- **Discovered certificates now reach the certificate inventory.** The
  dashboard counted them as unmanaged but `/certificates` (and the Estate =
  Unmanaged filter) never listed them: discovery wrote NULL `issuer_cn` /
  `key_size_bits`, the inventory loader scanned those into plain values and
  skipped every such row, and the inventory was only loaded at startup. Discovery
  now writes issuer CN, key size and the stored key algorithm; the loader
  tolerates NULLs in every nullable column; and the provider merges new or
  re-scanned discovery rows (unmanaged/external only) from the table within
  seconds, no restart. Discovered certificates stay `unmanaged`/`discovered`.
  Discovery scans no longer overwrite the risk of a managed certificate, and the
  Postgres upsert now sends real arrays for `subject_alt_names`/`risk_flags`.
- **SELF_SIGNED is flagged for `openssl req -x509` certificates.** These carry
  `CA:TRUE`, which exempted them. The leaf a server presents is now flagged
  when its subject equals its issuer and its own signature verifies under its
  own key; self-signed roots higher in a served chain stay unflagged.
- **HOSTNAME_MISMATCH no longer fires on every IP-target scan.** An IP-literal
  target only flags a certificate that has IP SANs none of which match; a
  DNS-only certificate reached by IP is not a mismatch. (The mismatch is now a
  per-endpoint fact, so it no longer depends on scan order; see below.)
- The Audit page's Resource column is readable: `GET /api/v1/audit` now adds a
  read-time `resource_name` (certificate common name, CA/template display name,
  "<template> for <CN or requester>" for approvals, notification rule name,
  scan target), resolved once per request and only for resources the caller may
  read. The stored record and `resource_id` are unchanged. The UI shows the name
  with the type and a shortened ID beneath it, and the CSV export gains a
  trailing `resource_name` column.
- A `certificate.issue` row recorded when approval is required now carries the
  `approval_id` in its change summary. Rows written before a certificate exists
  (failures, denials, pending approval) intentionally keep the collection name
  `certificates` as `resource_id`; successful issues already record the issued
  fingerprint.
- **One counting rule for certificate totals.** Pages disagreed on the same
  estate (e.g. 49 on the dashboard, expiry timeline and posture reports vs 39
  on the CA hierarchy) because revoked certificates were counted by some and
  not others. An *active* certificate is now one that is not revoked and not
  superseded by a renewal (`internal/bootstrap/certificate_active.go`, mirrored
  in the UI by `isActiveCertificate`). The dashboard summary (`total`,
  expiring/expired, estate split), per-CA "N certs", expiry timeline, crypto
  posture, executive summary, PQC countdown/migration/waves, algorithm sunset,
  compliance evidence and the dashboard expiry horizon all use it. The
  dashboard summary gains a separate `revoked` figure. The certificate
  inventory remains a record listing and is relabelled "N records (revoked and
  superseded included)"; status filters are unchanged. Per-CA counts now also
  keep certificates whose status was set to `expired` / `reissue_required`
  (only revoked and renewed ones leave the count).
- `POST /api/v1/certificates` and `POST /api/v1/certificates/{fingerprint}/renew`
  responses now include `key_algorithm_display` (e.g. `ML-DSA-65`), as list and
  get already did. It was derived on the stored copy only.

## [0.9.1] - 2026-10-14

### Fixed

- **A hub started in a directory without `./var` no longer 503s on file-backed
  templates, CAs and certificates.** The file providers wrote with `os.WriteFile`
  and never created their data directory (audit and SQLite already did). They now
  create it (0700) at startup and before each write.
- **`KRYPTKEEPER_ORG_NAME` now sets the bootstrapped root CA's organization.**
  It was documented next to the root-CA settings but only read for evidence-pack
  PDFs, so the auto-created root always carried `O=Kryptkeeper`. Unset or blank
  keeps `O=Kryptkeeper`; it has no effect on a root that already exists.
- **Templates page no longer shows "Issued 0" for templates that issued
  certificates.** The file-backed template store hardcoded `issued_count` to 0 and
  nothing ever updated it. The count is now derived from the certificate
  inventory on list and get, and deleting a template that has issued
  certificates is refused with `409` as the field always implied. Also fixes
  `GET /certificates?template_id=` being silently ignored by the in-memory
  index.
- **ML-DSA issuance and renewal are now recorded.** `crypto/x509` reports an
  ML-DSA subject key as `unknown`, which the `certificates.public_key_algorithm`
  CHECK rejects, so the hub signed the certificate and then answered `503
  certificate was signed but could not be recorded`. A single helper
  (`ca.StoredPublicKeyAlgorithm`) now derives the stored name from the SPKI OID
  (`ML-DSA`; hybrid certs keep their classical subject algorithm) at every site
  that persists it: issue, renew, import, ACME revoke, discovery and service-mesh
  scans. `key_size_bits` stays NULL-equivalent (0) for ML-DSA.
- **PQC readiness and quantum-safe numbers now agree on every page.**
  Crypto Posture, the PQC countdown and the PQC migration roadmap each
  computed them separately: the posture panel omitted leaf-only certificates
  (0 beside a 12% tile), and the roadmap excluded them (63% vs the countdown's
  75%). One definition (`pqc.ReadinessTally`) now feeds all three: quantum-safe
  is full-chain PQC only, `quantum_safe_leaf_only` (PQC key under a classical
  chain) is counted separately, hybrid counts as migration-ready, and
  `pqc_score_percent` = (quantum-safe + leaf-only + migration-ready) / total.
  `quantum_safe_percent` is now full-chain only (it previously included
  leaf-only); the roadmap response gains `quantum_safe_leaf_only`,
  `not_applicable`, `pqc_score_percent` and `quantum_safe_percent`, and the UI
  renders them instead of recomputing.
- **ML-DSA certificate authorities can be created.** `POST /api/v1/cas` now
  accepts `ML-DSA-44`, `ML-DSA-65` and `ML-DSA-87` (case and separators
  ignored, so `mldsa65` works), the OpenAPI schema lists the enum, the New CA
  form offers them, and unsupported values return a message naming the
  supported set. ML-DSA CAs still require the software key backend.
- **Certificate detail shows the ML-DSA parameter set.** The API adds a
  derived `key_algorithm_display` (e.g. `ML-DSA-65`, read from the key's OID);
  the stored `public_key_algorithm` value is unchanged.
- **ML-DSA CSRs under the standard PEM label no longer fail with 503.**
  OpenSSL 3.5+ emits ML-DSA PKCS#10 requests as `CERTIFICATE REQUEST`; the hub
  routed by label only, so they reached `crypto/x509`, which cannot verify the
  signature, and the failure surfaced as `503 certificate unavailable`.
  Issue and renew now route by the request's public-key algorithm OID (ML-DSA
  self-signature still verified, no parser fallback). Invalid or unsupported
  CSRs now return `400 invalid CSR: signature invalid or unsupported key
  type`, and an inactive or keyless issuing CA returns `409`, on both
  `POST /certificates` and `POST /certificates/{fingerprint}/renew`; 503 is
  kept for genuine backend failures. See README "Issuing post-quantum
  (ML-DSA) certificates".
- **UI shows names instead of IDs:** Approvals shows template and CA names,
  and Revocation Activity groups by CA name. Internal ticket references were
  removed from on-screen text. The Audit page has a "Hide read-only events"
  toggle (off by default; CSV export stays complete).

## [0.9.0] - 2026-10-12

This is the first public release of Kryptkeeper. Earlier entries (under
"Internal milestones" below) were internal milestones and were never
released publicly. This release covers agentless Windows enrollment (W18), a
real-client UAT programme (W19), and release readiness, delivery plugins,
and a security hardening pass (W20).

**Operators: read "Upgrade notes (breaking or behaviour changes)" below before
starting a v0.9.0 hub.** Several secure-by-default changes need configuration.

### Added

- **Multi-tenancy is experimental** (owner decision 2026-10-09). With
  `MULTI_TENANCY=on` the hub refuses to start unless
  `KRYPTKEEPER_MULTI_TENANCY_EXPERIMENTAL=accept-risk` is set; the UI labels
  it Experimental. Tenant isolation is not a security boundary (audit A01-001,
  A01-002, A01-004/005, A01-006, A01S-3); fixes are scheduled for v0.10. See
  `docs/design/TENANCY_POSTURE.md`.
- **WinRM/IIS agentless lifecycle** (W18): HTTPS WinRM discovery and IIS
  certificate install as a hub feature — credential preflight
  (`POST /api/v1/credentials/{id}/preflight`) that verifies a stored
  Windows credential without touching the host state; discovery, renewal,
  and install now record into the unified inventory for WinRM, ACME, EST,
  SCEP, and CMP issuance alike, all through one recorder seam. NTLM-sealed
  WinRM over plain HTTP is verified against a real Windows listener, and
  macOS agentless install into the System keychain over SSH is available.
- **TLS-by-default hub listener** (W19): Compose now runs the API over
  HTTPS out of the box (`KRYPTKEEPER_TLS_DISABLE=false`), exporting the CA
  certificate (never key material) to a dedicated `tls-trust` volume for
  clients to trust; plain HTTP remains available as an explicit opt-out.
  The agent trusts a hub-issued certificate via `KRYPTKEEPER_HUB_CA_CERT`
  / `KRYPTKEEPER_HUB_CA_CERT_FILE` (no skip-verify option exists).
- **Windows autoenrollment via WSTEP/XCEP** (W18-08, W19-10, W20-08): GPO-driven
  machine and user-context autoenrollment and renewal proven on a
  domain-joined Windows 11 client. WSTEP/XCEP is Kerberos-authenticated
  (keytab + SPN), and renewals are audited as renewals.
- **WSTEP template policy** (W20-09, W20-15): the template a request names
  is enforced (algorithms, minimum key size, EKUs, maximum validity), that
  validity is the issued validity, and the inventory row records the
  governing template.
- **Template enrollee type** (W20-17): templates are for machines or users
  (`enrollee_type`, default machine). XCEP offers, and WSTEP issues, only
  templates of the caller's own kind; the UI gains an "Issued to" selector.
- **CRL/OCSP pointers on every issuing path** (W20-10, W20-12): ACME, EST,
  SCEP, CMP, WSTEP, the API, approvals and connectors all embed CRL/OCSP
  pointers (configured per CA or derived from
  `KRYPTKEEPER_REVOCATION_BASE_URL`); an opt-in plain-HTTP revocation
  listener (`KRYPTKEEPER_REVOCATION_HTTP_ADDR`) serves only `/crl/` and
  `/ocsp`, and the RFC 5019 OCSP GET form now works.
- **EST authentication** (W20-14): HTTP Basic (bcrypt users limited to
  DNS suffixes) and TLS client-certificate authentication; re-enrollment
  requires a hub-issued certificate. EST enrollment is off unless configured.
- **SCEP one-time challenges** (W20-16): enrollment needs a one-time
  challenge minted for one device's names via `POST /api/v1/scep/challenges`
  (pki-admin or pki-operator; default 1 h, at most 24 h; only the SHA-256 is
  stored). `KRYPTKEEPER_SCEP_ENABLED=true` turns SCEP on; the static shared
  challenge and the unauthenticated `/scep/mscep_admin` are gone.
- **Delivery plugin system** (W20-19..22): WebAssembly delivery plugins
  run in a sandbox (wazero; no filesystem, environment or sockets; capped
  memory and time) with a Go SDK and conformance kit. The hub stores plugin
  versions, requires admin approval for High/Critical capabilities, and
  renews `plugin` install-mode targets through their plugin. A new
  Automation, Delivery Plugins page shows each plugin's capabilities in
  fixed wording. F5 and Citrix ship as first-party plugins; **they are
  verified only against mock devices and have not yet been verified on a
  real F5 or Citrix device.** `KRYPTKEEPER_DELIVERY_PLUGINS=off` is the
  kill switch.
- **Plugin signatures and trust tiers** (W20-24): publishers sign the
  manifest with `cosign sign-blob`; the hub verifies offline. Plugins are
  first-party (key compiled into the hub), verified (key listed in
  `KRYPTKEEPER_PLUGIN_TRUSTED_KEYS`), or community (unsigned); a signature
  that verifies against neither is refused.
- **ACME upstream dns-01 via Cloudflare** (W20-29): the upstream ACME
  connector can validate with `challenge: "dns-01"`, `dns_provider:
  "cloudflare"`, with the token held in the connector's outbound
  credential. Covered by unit tests against an in-memory zone and a fake
  Cloudflare API; **the live Let's Encrypt staging run is still pending.**
- **Release pipeline** (W20-02): a `v*` tag drives GoReleaser to build
  archives, checksums, CycloneDX SBOMs, deb/rpm packages and multi-arch
  images, all signed keyless with Sigstore. The multi-arch image build and
  push has not been exercised end to end yet.
- **SSH CA verified against real OpenSSH** (W20-26, FG-4): a live test with a
  stock OpenSSH server that trusts only the hub's CA passes (22 checks),
  including refusals for `root`, a missing `template_id` and a host outside
  the template's `host_patterns`.
- **Cloud Keys page** (read-only): Analysis, Cloud Keys (`/inventory/keys`) lists
  AWS, Azure and GCP key inventory with provider and search filters, per-source
  status, and partial-failure, empty and 403 states. Visible to roles holding
  `key.manage` or `report.read`, which includes viewers (owner decision
  2026-10-09; CLOUD-001).
- **Unattended auto-renewal** (PR #88): the scheduler now renews and installs
  for `ssh`, agent, `f5`, `citrix`, `k8s` and `iis` targets that opt in with
  `auto_renew`; push targets need only a `credential_ref`. An opted-in target
  that is skipped is logged with the reason. Proven live with a harness that
  only waits (`tests/live/autopilot`): the new serial chains to the hub CA, the
  reload ran, the key is 0600, the audit trail names the scheduler, and a
  failing install rolls back with a failure event and an owner notification.
- **Install retry with backoff** (PR #88): a failed scheduled install is
  retried up to 5 times with exponential backoff, each attempt audited
  (`attempt=n/5`); the owner is notified on the first failure and again on the
  last (`certificate.renew_execute_gave_up`). The scheduler status gains
  `pending_installs` and `gave_up_installs`. The retry renews from the newest
  certificate in the chain, because the hub-generated key of a failed attempt
  is destroyed.
- **`verify_host_port` on targets** (migration `000071`): scheduled
  post-install verification dials `host:port` instead of always `<host>:443`;
  validated on create and patch, default unchanged.
- **`RENEWAL_POLL_MINUTES`**: sub-hour scheduler cadence; wins over
  `RENEWAL_POLL_HOURS`. See `docs/guides/standard-environment.md`.
- **SIEM forwarding is live** (FB-06): one router is built at startup and wraps
  the audit provider, so every audit write (protocol, scheduler, ceremonies)
  reaches the configured webhook or syslog sink through a bounded drop-new
  queue, over the egress-guarded client. Before this, only the Test button
  sent anything.
- **Audit-append failure counter** (FB-04): `kryptkeeper_audit_append_failures_total`.
- **Template name policy** (FG-9, SUP-A04-3): templates take an optional
  `name_policy` (DNS suffixes or exact names, IP and URI SAN allowance, URI
  prefixes, CN-must-be-SAN), enforced in the CA engine on the names about to be
  signed, so API, renewal, bulk reissue and WSTEP issuance are all covered.
- **CMP sender, replay and suffix binding** (FG-9, SUP-A04-2): the `senderKID`
  is compared with `KRYPTKEEPER_CMP_REFERENCE`, a reused
  `transactionID`+`senderNonce` is refused, and
  `KRYPTKEEPER_CMP_ALLOWED_DNS_SUFFIXES` limits the names a secret holder can
  obtain.
- **Template SSH policy** (FG-4, A01S-4): templates carry `ssh_policy` (cert
  types, allowed principals, host patterns, max TTL); the template editor has
  an SSH policy section. The template id is recorded on the SSH certificate
  (migration `000070`).
- **Bearer-token role mapping** (FG-5, D-125): `APP_AUTH_ROLE_CLAIM` and an
  ordered `APP_AUTH_ROLE_MAP_JSON` map IdP claims to roles.
- **Argon2id login hash** (FG-7): `kryptkeeper --hash-password` emits the
  value for `APP_AUTH_LOGIN_PASSWORD_HASH`.
- **Outbound egress guard** (FG-8): a guarded `internal/egress` HTTP client for
  webhooks, Slack, PagerDuty, inventory sources, the ACME connector and SIEM
  sinks. `KRYPTKEEPER_EGRESS_DENY_PRIVATE=true` also blocks private ranges.
  Discovery gains `KRYPTKEEPER_DISCOVERY_DENY_CIDRS` and
  `KRYPTKEEPER_DISCOVERY_MAX_TARGETS`.
- **Key-store hardening knobs** (FG-11): `KRYPTKEEPER_KMS_TAGS`,
  `KRYPTKEEPER_GCP_KMS_PROTECTION` (`hsm` default, `software`) and
  `KRYPTKEEPER_AZURE_KEY_HSM` (default true); minimal IAM policy in
  `docs/ops/CLOUD_KMS.md`.
- **Other new settings**: `KRYPTKEEPER_KEY_DUAL_CONTROL`,
  `KRYPTKEEPER_DISABLE_BOOTSTRAP_TOKEN`, `KRYPTKEEPER_ALLOW_NO_POLICY`,
  `APP_SAML_ALLOW_IDP_INITIATED`, `APP_TRUSTED_PROXY_CIDRS` (now documented in
  `env.example`), `KRYPTKEEPER_MCP_HTTP_TOKEN` and
  `KRYPTKEEPER_AGENT_CREDENTIALS_FILE`.
- **CA PEM and fullchain download documented**: the README first run now covers
  template, CSR, issue, `GET /cas/{id}/chain?format=pem` and `openssl verify`;
  `.../download?format=pem&include_chain=true` returns the conventional
  fullchain (leaf plus issuing intermediates, root excluded).
- **First-boot root CA on by default in `env.example`**
  (`KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true`); it is never consulted once a CA
  exists, so it is safe to leave set.
- **Operator guide for ordinary servers**
  (`docs/guides/standard-environment.md`) and a **v0.9 feature validation
  inventory** (`docs/release/FEATURE_VALIDATION_v0.9.md`).

### Changed

- **Project identity settled** (W20-06): GitHub `bpmforge/kryptkeeper`,
  images `ghcr.io/bpmforge/*`, security contact `security@kryptkeeper.io`;
  all references swept.
- **CI fix and open-source hygiene** (W20-01, W20-03): `ci-main` gains lint,
  UI-gate and OpenAPI-drift coverage; README quickstart matches the
  TLS-by-default Compose; lab addresses replaced with documentation-range
  placeholders.
- **TLS client certificate request is opt-in** (W20-13): the hub no longer
  requests one unless `KRYPTKEEPER_TLS_REQUEST_CLIENT_CERT=true`.
- **API spec** (W20-28): `docs/openapi.yaml` now documents the PQC wave
  execute and approve routes, and `scripts/validate-openapi.sh` also checks
  that every path the UI calls is documented.
- **Toolchain**: Go 1.26.9 and `golang.org/x/net` v0.60.0, picking up fixes
  for published advisories.
- **Key export routes answer 202 under dual control** (FG-2, D-122): backup,
  escrow, escrow recovery, leaf escrow, leaf-escrow recovery and BYOK export
  now follow the propose, approve, redeem flow that `POST /keys/{id}/export`
  already used (202 plus `action_id`, then retry with `approved_action_id`).
- **API keys resolve to a human** (FG-2): keys record `created_by`, so a key
  cannot approve its minter's proposals, and the bootstrap token can no longer
  approve or reject.
- **Bearer tokens are read-only by default** (FG-5, D-125): in `AUTH_MODE=jwt`
  and `oidc` a valid token is `viewer` unless a claim maps to a role.
- **SSH certificates need a template** (FG-4, D-124): `POST /ssh/certificates`
  requires `template_id`; a TTL over the template maximum is refused, not
  clamped.
- **Users, roles and API keys: grant only what you hold** (FG-3): role strings
  are validated (400), refusals return 403 plus an audit event, and a delegate
  can change or delete only users and roles it could itself grant.
- **`/audit` and `/audit/transparency/*` need `audit.read`** (FG-3): granted to
  pki-admin, auditor, pki-auditor and custom roles that hold it; refused to
  mcp-agent, service-account, viewer and operator. The MCP `audit_query` tool
  is removed (FG-10).
- **Cloud key inventory needs `key.manage` or `report.read`** (FG-3, FG-11) and
  returns generic errors instead of ARNs.
- **Proposal bodies are capped at 64 KiB** (FG-3, LLM-005); the MCP HTTP
  transport at 1 MiB.
- **ACME issues only validated DNS names** (FG-1): `dns` identifiers only;
  wildcards through dns-01 only; the CSR must name exactly the order's
  identifiers; `localhost` names are refused; single-label intranet names are
  allowed. ACME and CMP refuse RSA keys under 2048 bits (ECDSA P-256/384/521
  and Ed25519 are accepted). http-01 uses a guarded client: redirects only to
  ports 80/443, and loopback, link-local, metadata and NAT64-embedded targets
  are refused.
- **CMP requires `transactionID` and `senderNonce`** (FG-9) and refuses a
  reused pair (in memory, per process).
- **OCSP answers per issuer** (FG-9, SEMGREP-012/013): an unknown issuer gets
  `unauthorized`, a store failure gets `tryLater`, the CertID hashes are
  verified against the resolved issuer, responses are cached per issuer and
  echo the request's hash algorithm, and SHA-256/384/512 CertIDs are accepted.
- **ACME revocation resolves the issuing CA or fails** (FG-9, SEMGREP-014)
  instead of recording against the default CA.
- **Renewal applies the predecessor template's name policy only** (SUP-A04-3),
  not the full template, so PQC migration waves can still renew a
  classical-template certificate onto ML-DSA; a template lookup error fails
  closed.
- **Login and sessions** (FG-7): login passwords are Argon2id (legacy
  HMAC-SHA256 values still verify and are upgraded in memory on first login);
  logout revokes the login session's refresh tokens; refresh re-reads the
  user's role and status; failures back off per account with the same answer
  for known and unknown emails.
- **OIDC and SAML** (FG-7): the OIDC callback is bound to the browser by a
  flow cookie and an ID-token nonce; a first login that links by email needs
  `email_verified`; unknown-`kid` JWKS refetches are limited to one per 30 s;
  OIDC discovery, JWKS and token exchange refuse redirects to non-https URLs;
  SAML needs `InResponseTo` naming a pending request, refuses a replayed
  assertion, and refuses IdP-initiated responses unless
  `APP_SAML_ALLOW_IDP_INITIATED=true`.
- **HTTP hardening** (FG-7): `nosniff`, `X-Frame-Options: DENY`,
  `frame-ancestors 'none'`, `Referrer-Policy: no-referrer` and HSTS on TLS on
  every response; `Cache-Control: no-store` on `/api/`; the session cookie is
  `Secure` only when the request is TLS or a trusted proxy says so; redirect
  targets must be relative.
- **Client IP resolution** (FB-10, OWASP-001): one resolver for rate limits and
  audit source IP; behind a trusted proxy it takes the rightmost untrusted
  `X-Forwarded-For` entry. `nginx.conf` now appends to `X-Forwarded-For`.
- **Pre-auth request bodies are capped** (FB-14): login, refresh and API-key
  create 16 KiB; agent register 16 KiB, renewal result 64 KiB, inventory
  2 MiB; SCIM 1 MiB; excess returns 413. The agent enrolment gate's error text
  goes to the log, not to the caller.
- **Hub fails closed on user-store errors for login sessions** (FB-03): the
  affected requests get 503 (authz-check, refresh) or 401, and an
  `authz.userstore_error` audit row is written at most once per 30 s.
- **Cloud KMS** (FG-11): AWS keys are tagged `kryptkeeper:managed` and
  `key-id`, GCP and Azure labelled likewise; GCP creates HSM keys and Azure
  EC-HSM/RSA-HSM by default; key ids are validated; AWS calls have a 30 s
  deadline.
- **Delivery plugins** (FG-10): without `elevated_exec`, the host refuses
  escalation tools (sudo, su, pkexec and similar), shells and
  interpreters with an inline command, and wrappers launching either; any
  network capability, including `hosts_from_credential`, is High tier and
  needs a second admin's approval.
- **MCP HTTP transport** (FG-10): needs `KRYPTKEEPER_MCP_HTTP_TOKEN` (32+
  characters, constant-time check), Host and Origin allowlists
  (`KRYPTKEEPER_MCP_ALLOWED_HOSTS`, `KRYPTKEEPER_MCP_ALLOWED_ORIGINS`) and a
  1 MiB body cap; tool results carry an untrusted-data envelope.
- **Startup is stricter** (FG-5, FB-01, FB-02): auth configuration errors,
  a failed issuance-policy build, and a `ListCAs` error are fatal;
  `KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT` is parsed case-insensitively and accepts
  `1`.
- **Compose, Helm and Terraform** (FG-12): Compose requires
  `KRYPTKEEPER_KEYSTORE_PASSPHRASE`, different from `APP_BOOTSTRAP_TOKEN`; the
  Helm chart's probes, Service and ServiceMonitor follow the TLS setting and it
  adds `tls.existingSecret`, `tls.extraSANs` and `extraEnv`; the Terraform
  module serves TLS and requires a digest-pinned image.
- **Reports** (FB-12, FB-13): the SOC2-CC6.7 control downgrades from pass to
  warn when any certificate has unknown expiry, and names them; risk score and
  risk flags share one ladder with an injected clock.
- **Finding exceptions are hidden** (FB-09): the UI and docs no longer claim
  exceptions or "suppressed" findings; the feature returns in v0.10.
- **Console agent keeps its registration in a private file** (FG-13): see
  `KRYPTKEEPER_AGENT_CREDENTIALS_FILE`; the bearer token is no longer logged.
- **Dependencies and licences** (FG-13): Terraform provider gRPC v1.84.0, x/net
  v0.60.0, x/text v0.42.0; `react-router-dom` ^7.18.2 (`npm audit
  --omit=dev` reports 0); shadcn and msw moved to devDependencies; Geist (OFL)
  and HashiCorp MPL-2.0 notices added.
- **CI and release hygiene** (FG-12, FG-13): every action pinned to a full
  commit SHA, `permissions:` set on every workflow, dispatch inputs and secrets
  passed through `env`, cosign key read from the environment, job base image
  pinned by digest.

### Fixed

- **Internal callers see every certificate** (RC1 H2/H3): the renewal
  scheduler, reports, executive summary, bulk revoke, CA-compromise response,
  CBOM, PQC and anomaly/SLO jobs listed certificates through the HTTP list
  path, which caps a page at 100, so on a larger estate they silently saw only
  the first 100 (25 for CA compromise). They now iterate the whole inventory;
  the HTTP list keeps its 100-row page cap. List pages no longer copy and sort
  the whole inventory (at 50k certificates a page went from 29 ms to 0.3 ms,
  compliance evidence from 14 s to 40 ms).
- **Issuance no longer runs the keystore KDF**: reading a CA key's algorithm
  re-derived the 64 MiB Argon2id key on every issuance; it now comes from the
  cached signer (`IssueCertificate` benchmark 67.2 MB/op to 28 KB/op, 17.9 ms to
  0.14 ms, as recorded in the message of commit 155acbac; the benchmark output is
  not stored under `docs/`). Issuance cost no
  longer grows with inventory size (key-reuse and per-CA counts are indexed).
- **Login password hashing is bounded** to a few concurrent Argon2id runs per
  hub, and a waiting login gives up when its request ends (RC1 M4). The
  protocol rate limiter now evicts idle keys and caps its table (RC1 M5).
- **CA-key compromise can flag certificates for reissue**: the flow wrote
  `reissue_required`, which both certificate stores and the database rejected
  (migration `000073` widens the status constraint). A failed certificate
  update no longer leaves the in-memory inventory ahead of the database.
- **Reports count unknown expiry** instead of skipping it: crypto posture
  `expiry_buckets.unknown`, executive summary `expiry_unknown`, expiry timeline
  `unknown_expiry`.
- **The cert-manager issuer Helm chart renders**: its labels helper glued two
  labels onto one line, so every manifest failed to parse.
- **Oversized request bodies answer 413** on `/certificates`, `/credentials`
  and `/templates` (create, replace, patch, clone, revoke, renew, import,
  ownership) instead of a generic 400. Template bodies, previously uncapped,
  are limited to 256 KiB. `/targets` still answers 400 (RC1).
- **SIEM forwards every audit event**, not just seven actions (N-04). Known
  actions keep their event types (`cert.issued`, `auth.login_failed`, ...);
  others are sent under their audit action name. Set
  `KRYPTKEEPER_SIEM_ACTIONS` (comma-separated, exact or `prefix.*`) to
  restrict. The payload still carries no change summary, user agent or session.
- Certificate and key-escrow download filenames are sanitized before they go
  into `Content-Disposition` (RC1).
- The hub exits with a clear message when `KRYPTKEEPER_KEYSTORE_DIR` cannot be
  created, instead of failing later (FB-02).
- Docs no longer claim agentless SSH certificate discovery; only SSH install is
  live. The scanner exists but nothing calls it yet (AS-03).
- ~40 defects found and fixed via the W19 UAT programme running real
  clients and CAs against every enrollment protocol: ACME (certbot),
  EST/SCEP/CMP interoperability, CRL/OCSP correctness, PKCS#11 HSM paths,
  Kubernetes/cert-manager push and discovery, service-mesh issuance, and
  agent hub-CA trust. See [`docs/UAT_PLAN.md`](docs/UAT_PLAN.md) for the
  scenario-by-scenario evidence and [`docs/STATUS.md`](docs/STATUS.md)
  (2026-09-10/11 entries) for the day-by-day record.
- WSTEP renewals signed with Windows' two-signer request are now recognised
  and audited as renewals (W20-11); template edit in the UI no longer drops
  fields on PUT (W20-17).
- **`include_chain` was ignored on CA-backed download**: even a leaf issued by
  an intermediate came back as the bare leaf. It now returns the leaf plus the
  issuing intermediates, root excluded.
- **A failed auto-renew was audited as success**: the scheduler wrote
  `outcome=success` for `renew_execute_failed` and `_partial`. It now records
  failure plus the install outcome.
- **No owner notification after a failed auto-renew**: the reminder was judged
  against the cooldown the attempt had just set, so it was always suppressed.
- **A failed scheduled install was never retried**: the failed attempt left a
  successor that marked the predecessor superseded, so the host kept serving
  the old certificate indefinitely.
- **Opted-in `f5`, `citrix`, `k8s` and `iis` targets were never auto-renewed**;
  only `ssh`, keychain and plugin targets were.
- **Certificates pinned to an upstream connector renewed from the hub CA**
  (FB-07): they now renew upstream, and fail closed if the pinned connector
  cannot be resolved. Manual-execute and rollout executors use the same
  connector registry.
- **The issuance policy gate could be silently off** (FB-01): a policy-engine
  build error is now fatal unless `KRYPTKEEPER_ALLOW_NO_POLICY=true`.
- **A transient `ListCAs` error could mint a second root** (FB-02) when
  `KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT` was set.
- **A fresh Compose install crash-looped with "no CA configured"**: the
  first-boot flag shipped commented out. The fatal message now names the
  `.env` line to add.
- **A deprovisioned user kept access during a user-store outage** (FB-03,
  A2A7-009): the check failed open for every login session.
- **Audit rows could be lost** (FB-04, FB-05): appends used the request
  context, so a client hang-up dropped them, and an approved action whose
  decision write failed returned 409 with no audit row. Appends are now
  detached with a 5 s bound and logged at ERROR; the approval path retries once
  and writes `action.approve` with outcome `executed`.
- **The default audit store lost events and slowed every request** (RC1 perf
  H1): the file provider rewrote the whole JSON array on each append without a
  lock and reset the file on a parse error (4 concurrent clients wiped about
  99.8 percent of the trail). The audit store now defaults to the database
  whenever the hub has one; the file store is append-only JSON Lines under a
  mutex, skips and counts a corrupt line instead of discarding history, and
  the hub refuses to start if the audit store cannot be opened.
- **Renewal retry state could silently reset** (RC1 N-01, N-02): a file audit
  store read error looked like "no failures", so a failing renewal retried on
  every tick; an unparseable failure timestamp disabled backoff. A read error
  now skips auto-renew for that certificate this tick (the expiry reminder
  still goes out) and a bad timestamp backs off from now.
- **Rate limits and audit source IP could be forged** (FB-10, OWASP-001): the
  leftmost `X-Forwarded-For` entry was taken from any peer.
- **The http-01 dial guard was weaker than the egress table** (FB-11): it let
  NAT64-embedded loopback and `0.0.0.0/8` through.
- **Compliance evidence reported a pass on missing data** (FB-12): unparseable
  expiry counted as healthy, and a `ListCAs` failure produced CA-health results
  from an empty list. The executive-summary and evidence endpoints now return
  503 (a failure audit event for the summary).
- **Key size was 0 for every hub-issued certificate** (FB-13, CX-005): size
  based policy never fired. Real sizes are computed (RSA modulus, EC curve,
  Ed25519 = 256), and rows stored with 0 are recomputed from the PEM on load.
- **Approvals could execute more than once** (FG-2, A01-003): approval now wins
  a pending to executing compare-and-set before the executor runs; losers get
  409.
- **Smoke OIDC section was silently skipped**: the RS256 JWKS generator never
  parsed its exponent, so the oidc-mode checks did not run. The suite now runs
  331 assertions and passes (2026-10-11, `docs/release/LIVE_RESULTS_v0.9.md`).
- **Demo mode** crash on the Expiry Timeline, and missing Approvals and PQC
  data.
- **A core-database failure no longer silently drops the CA to memory.** With
  `APP_CERTIFICATE_PROVIDER=ca`, a failure to open the core database or run its
  migrations now stops the hub instead of falling back to an in-memory CA whose
  root is lost on restart. Migration `000020_tenant_scoping` now tolerates a
  `pending_actions` table that already has the `tenant` column, which happened
  when a data directory was first used with a non-`ca` provider and then
  switched to `ca` (the `duplicate column name: tenant` failure reproduced in
  `docs/release/UPGRADE_TEST_v0.9.md`).
- **`KRYPTKEEPER_KEYSTORE_DIR` default follows the data directory.** When
  `KRYPTKEEPER_DATA_DIR` is set and the keystore directory is not, keys now go
  to `<KRYPTKEEPER_DATA_DIR>/keys` instead of `./var/keys`, which is not on the
  volume in a read-only container. An existing `./var/keys` that already holds
  keys is kept, with a warning. The resolved path is logged at startup.
- **API keys minted through the API now survive a restart.** Keys created with
  `POST /api/v1/api-keys` are persisted in the core database. Previously they
  lived in process memory and returned 401 after every restart. Without a core
  database they stay memory-only and the hub logs a startup warning.
- **API-key database writes no longer hold the auth lock.** Minting a key
  persists it before taking `apiKeyMu`, with a timeout, so a stalled core
  database cannot block every authenticated request. The unused
  `Authenticator.DeleteAPIKey` wrapper is removed (`RevokeAPIKey` is the one
  path).
- **Notification rules persist and fire under the `delivery` provider** (the
  Compose default). Rules created through the API were not stored under that
  provider, so nothing ever alerted. They are now kept in the notification
  database. Rule create validates input and returns 400 for an unknown channel
  (`email`, `slack`, `pagerduty`, `webhook`), an empty name or target, or a
  threshold outside 1-3650 days; the rule endpoints return 503 when the store
  is unavailable.
- **Template `validity_period` is honoured.** ISO-8601 (`P30D`, `P1Y`), Go
  durations (`72h`) and `90d` are parsed on issue and renew, clamped to the
  issuing CA's `NotAfter`, and capped at 7 days for short-lived templates.
  Previously every ISO value fell back to the 90-day default. An unparseable
  period now fails issuance and is rejected when the template is created.
- **Any purely additive migration is tolerated automatically.** The runner
  applies a migration made only of additive statements (no drops or
  rewrites) statement by statement and logs
  `statement already satisfied, skipping` for anything a store already
  created, instead of failing with a duplicate-column error. Migrations that
  are not purely additive still run in one transaction.
- **Postgres user store.** `GET /api/v1/users` and API-key minting returned 503
  on PostgreSQL because the user store used SQLite-only SQL and ids. Fixed;
  user ids are UUIDs on Postgres.
- **Postgres notification ids.** Test and retry deliveries on PostgreSQL
  failed because they minted non-UUID ids (`notif-<nanos>`, `retry-<nanos>`)
  for a UUID column. The database now assigns the id; an id that is not a UUID
  is reported as not found.
- **Root-CA key ceremonies work on SQLite and PostgreSQL** (migration
  `000075` widens the CA `status` check to include `pending_ceremony`).
  Before, creating a root through a ceremony could leave an unapproved root
  CA active.
- **`ct_findings` is created at startup.** No migration owned the table, so a
  `ca`-provider hub recorded CT findings into a table that did not exist.
- **Audit rows with outcomes `skipped`, `pending_approval`, `proposed`,
  `executed`, `issuance_failed` or `partial`, and actor type `workload`, were
  silently dropped** on the database audit store (the CHECK only allowed
  success, failure and denied). Migration `000076` widens it, the outcome is a
  typed vocabulary at every call site, and the audit store widens a narrow
  table that has its own DSN. See upgrade notes 63 to 66.
- **`GET /api/v1/audit?outcome=` was ignored**, so the UI outcome filter did
  nothing. It filters now and rejects unknown values with 400.
- **Non-delivering notification providers recorded alerts as sent.** `file` and
  `db` now skip and audit `skipped` instead (note 67).
- **Notification rule alerts could burst and grow without bound**: capped per
  scan (`KRYPTKEEPER_RENEWAL_RULE_SEND_CAP`), sent by 8 workers, delivery log
  limited to 10,000 entries (note 68).
- **SQLite writers from different stores failed at once with "database is locked"**:
  the default `kryptkeeper.db` DSN used WAL but no busy timeout (SQLite's
  default is 0), and every store holds its own pool on that file. The DSN now
  sets `_busy_timeout=5000`; a DSN you supply yourself (`APP_*_DB_DSN`) is used
  as given.
- **Template validity could overflow** when several large ISO components were
  summed; the total is now bounded at 100 years (note 69).

### Security

- **No audit event is silently lost any more** (RC7): approval holds, dual-control
  proposals, skipped alerts and workload attestations were rejected by the
  database audit store's CHECK and never stored in rc builds 1 to 6. They are
  stored from rc.7 (upgrade notes 63 and 64).
- **The CA key-consistency check failing is fatal at startup** unless
  `KRYPTKEEPER_ALLOW_MISSING_CA_KEYS=true` (note 70).
- **Unauthenticated `POST /api/v1/spiffe/workload-svid` now caps its body**
  at 16 KiB and answers 413 (RC1-B-03).
- **Template name policy now covers the subject CN** (RC1-C-01). With
  `allowed_dns_suffixes` or `allowed_dns_names` set, a CN that is not one of the
  SANs must itself satisfy the DNS restriction, so a CN-only CSR can no longer
  bypass it under the default `cn_must_be_san=false`. A free-text CN such as
  "Alice Smith" is refused on such templates; put it in a template without a
  DNS restriction, or use a hostname CN.
- **`GET /api/v1/users` requires `user.manage`** (admin roles, or a custom role
  granted it). It was readable by any authenticated principal, including
  viewer and mcp-agent (RC1).
- **The hub refuses placeholder secrets**: a keystore passphrase, bootstrap
  token, login/JWT signing secret or pepper that starts with `change-me`
  (case-insensitive) stops startup, so `cp env.example .env` can no longer run a
  hub with a public passphrase (AS-01).
- The OIDC RS256 verifier rejects JWKS RSA keys under 2048 bits, matching the
  ACME JWS verifier, and its rejections (alg none, HS256 confusion, wrong
  iss/aud, expired, nbf, unknown kid) are now covered by a table test (AS-02).
The 2026-10-09 deep audit (OWASP Web A01-A10, SAST, secrets, dependencies,
OWASP LLM, cloud, IaC/CI, STRIDE, 19 attack chains; challenger score 8/10)
found 3 CRITICAL and 9 HIGH findings. All are fixed or gated below; FG-6 is the
one deferred group. Report: [`docs/security/final-report.md`](docs/security/final-report.md);
residual risk: [`docs/security/OWASP_TRACKER.md`](docs/security/OWASP_TRACKER.md).
None of the issues below was ever in a public release.

- **Write authorization gate** (W20-26): read-only and `mcp-agent`
  principals could write through the API — create root CAs, templates and
  targets, and issue SSH certificates for any user. A central gate now
  refuses every `/api/v1` write (403 plus an `api.write` denied audit row)
  unless the principal holds a write-capable role or scope; `mcp-agent` may
  only POST pending actions.
- **Route-level write permissions** (W20-27): a pki-operator could invite a
  user with the pki-admin role and create tenants (privilege escalation),
  and pki-operator, service-account and approver principals could create
  root CAs and upstream connectors. Every write route now requires its one
  specific permission. Visible role changes: pki-operator can no longer
  write CAs, templates, targets, connectors, tenants or users;
  service-account and approver can no longer create CAs or connectors;
  service-account can no longer revoke.
- **FG-1, ACME issuance** (OWASP-A04-001 CRITICAL, A10-001, A04-002, A03-2,
  A04-004): with default config, anyone who could reach `/acme/` got a
  certificate for any DNS name, IP or SPIFFE ID, because `newOrder` accepted any
  identifier type and finalize let the CSR supply SANs and Subject. Only
  validated `dns` identifiers are accepted and the CSR must match the order;
  http-01 uses a guarded client (10 s timeout, no proxy, redirects limited to
  ports 80/443, no loopback or metadata targets, body never logged); the nonce
  store evicts oldest-first instead of wiping. Live certbot and lego: 28/28.
- **FG-2, key egress and separation of duties** (A2A7-001, A07-4, LLM-006,
  A01-003): backup, escrow and BYOK export bypassed key dual control, and an
  admin could mint an API key under any `principal_id` and approve their own
  proposals. All key egress routes now use dual control (on by default,
  D-122), separation of duties follows the human behind a key, and approvals
  execute once.
- **FG-3, RBAC escalation and sensitive reads** (TM-08, LLM-001, A01-004,
  CLOUD-001, LLM-005): a custom role with `user.manage` could make itself or
  anyone pki-admin, and any principal could read `/audit`. Grants are limited
  to what the caller holds, audit reads need `audit.read`, and the cloud key
  inventory needs `key.manage` or `report.read`.
- **FG-4, SSH CA policy** (A01S-4, D-124): a pki-operator could mint an SSH
  certificate for `root`. Certificates are now issued only within a template's
  `ssh_policy`.
- **FG-5, token and secret hardening** (A02-3, A02-4, A07-6, D-125): in OIDC
  mode with an empty issuer or audience, any IdP token became a service-account
  that could issue; HS256 secrets only had to be non-empty. OIDC requires issuer
  and audience, `nbf` is checked, secrets under 32 bytes are startup errors,
  bearer tokens default to `viewer`, and the bootstrap token is compared in
  constant time, warned about under 32 characters, and can be disabled.
- **FG-6, tenant isolation (deferred to v0.10)** (A01-001 and A01S-3 CRITICAL,
  A01-002, A01-006, A01S-6, A01-004/005, A01S-5, A01-007): multi-tenancy ships
  as experimental (D-123) and tenant isolation is not a security boundary in
  v0.9. The hub refuses `MULTI_TENANCY` without
  `KRYPTKEEPER_MULTI_TENANCY_EXPERIMENTAL=accept-risk`. See
  [`docs/design/TENANCY_POSTURE.md`](docs/design/TENANCY_POSTURE.md).
- **FG-7, login and session** (A2A7-002..008, A02-1, A02-2, A02-6, A07-1..8,
  OWASP-003/004, SUP-A10-4, SPIFFE-L): HMAC password hash, logout that revoked
  nothing, a refresh that extended forever with the login-time role, email
  account linking without `email_verified`, SAML without `InResponseTo` or
  replay protection, a forgeable `Secure` cookie flag and no security headers.
  All fixed as described under Changed; SPIFFE SVID responses are `no-store`,
  rate limited and return generic errors.
- **FG-8, outbound egress policy** (SEMGREP-001/002, A10-002, A10-003, A04-005,
  SEMGREP-007): webhooks, inventory sources, the ACME connector health probe and
  SIEM sinks could be pointed at metadata or loopback addresses, and the ACME
  probe worked as a port scanner. One guarded client now covers them (private
  ranges optionally); the ACME connector reports a fixed health vocabulary.
- **FG-9, issuance policy** (SUP-A04-2, SUP-A04-3, SEMGREP-012/013/014): CMP
  issued any CSR names under one shared secret, templates could not restrict
  names, and OCSP signed `good` for issuers it did not serve. See Added and
  Changed for the template name policy, CMP binding and OCSP behaviour.
- **FG-10, plugins and MCP** (A08-001, SUP-A08-1, LLM-001/003/004/005): see
  Changed. The HTTP transport previously had no authentication, Origin check or
  body cap.
- **FG-11, cloud** (CLOUD-001/002/003/005/008, SEMGREP-003): KMS keys are
  tagged so IAM can be scoped, GCP and Azure keys are HSM-backed by default, and
  the Kubernetes connector's skip-verify option is removed in favour of a CA
  file.
- **FG-12, IaC and CI** (IAC-001..008, 014, 016, 017, DEP-011): the Terraform
  module served plain HTTP on a public IP with the bootstrap token in cleartext
  and secrets in state; Compose defaulted the keystore passphrase to the
  bootstrap token; Helm's TLS default crash-looped; workflows expanded inputs
  into shell and used mutable action tags. See Changed and Upgrade notes.
- **FG-13, dependencies and hygiene** (DEP-001/002/004/005, SG-DEP-001,
  SEC-04, SEMGREP-004): see Changed. The agent bearer token is no longer
  logged; `.gitignore` covers tfstate, kubeconfig, cosign keys and `.env.*`.
  The audit found no live secrets in code or git history and no CISA KEV
  dependency.
- **FG-14, documentation matches the code** (TM section 8.8): the threat model,
  architecture, tenancy posture and OWASP tracker no longer claim notification
  encryption, bcrypt, open audit access, or key-in-API-response behaviour the
  code does not have.
- **Dependencies**: Go 1.26.9 and `golang.org/x/net` v0.60.0 for published
  advisories.

### Upgrade notes (breaking or behaviour changes)

- **Placeholder secrets stop the hub.** If your `.env` still contains the
  `change-me-...` sample for `APP_BOOTSTRAP_TOKEN` or
  `KRYPTKEEPER_KEYSTORE_PASSPHRASE`, startup fails. Generate real values with
  `openssl rand -hex 32`. There is no passphrase re-seal tool: changing the
  passphrase of an existing keystore makes it undecryptable, so a pilot
  keystore created under the sample value must be rebuilt (restore the CA keys
  into a fresh keystore, see `docs/ops/DR_RUNBOOK.md`).
- **`GET /api/v1/users` is now admin-only** (403 for other roles); API clients
  that listed users with a viewer or operator credential need an admin or a
  custom role with `user.manage`.
- **SIEM volume rises**: all audit actions are forwarded by default. Set
  `KRYPTKEEPER_SIEM_ACTIONS` to keep the previous narrow set, e.g.
  `certificate.issue,certificate.revoke,ca.create,ca.suspend,ca.activate,auth.login,auth.login_failed`.
- **Templates with a DNS name policy** now also constrain the CN (see
  Security).
Read this before upgrading from an internal build. Each item names what
changes and what to do. The first public release has no earlier public version,
so "default" means the v0.9.0 default.

**Secrets and startup**

1. **Weak secrets are fatal.** `APP_AUTH_LOGIN_SIGNING_SECRET` (any login flow)
   and, in `AUTH_MODE=jwt`, `APP_JWT_HS256_SECRET` under 32 bytes stop the hub.
   Generate with `openssl rand -hex 32`. A bootstrap token under 32 characters
   only logs a warning.
2. **Auth configuration errors are fatal.** Validation errors now stop the hub
   instead of being logged. A missing bootstrap token (login enabled) and a
   missing API-key pepper (API-key auth off) stay warnings.
3. **Compose needs `KRYPTKEEPER_KEYSTORE_PASSPHRASE`**, different from
   `APP_BOOTSTRAP_TOKEN`; `docker compose up` refuses to start without it. The
   Helm chart requires `secrets.keystorePassphrase` and rejects equal inline
   values.
4. **Issuance policy engine failure is fatal.** Fix the policy store, or set
   `KRYPTKEEPER_ALLOW_NO_POLICY=true` to start without the gate (not
   recommended).
5. **A `ListCAs` error at startup is fatal** (it used to read as "no CAs" and
   could mint a second root). First-boot root creation needs
   `KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true` (now on in `env.example`).
6. **The bootstrap token can be disabled** with
   `KRYPTKEEPER_DISABLE_BOOTSTRAP_TOKEN=true` once real admins exist. It can no
   longer approve or reject pending actions.

**Authentication and authorization**

7. **Key dual control is ON by default.** Export, backup, escrow, escrow
   recovery, BYOK export, delete and rotate need a second human's approval
   (202 plus `action_id`; retry with `approved_action_id`; grant is single-use,
   10 minutes). Needs two real identities. Opt out with
   `KRYPTKEEPER_KEY_DUAL_CONTROL=false` (only the literal `false` disables it;
   a startup warning is logged).
8. **API keys resolve to the human who minted them.** Keys minted with the
   bootstrap token all resolve to the bootstrap holder and cannot approve each
   other's proposals. Provision a second admin through `APP_API_KEYS_JSON`, or
   use SSO or login users.
9. **Bearer tokens (`AUTH_MODE=jwt` or `oidc`) are read-only by default.**
   Tokens that used to issue certificates now get `viewer`. Set
   `APP_AUTH_ROLE_CLAIM` and `APP_AUTH_ROLE_MAP_JSON` (ordered
   `claim_value`/`role` pairs, first match wins). Unknown roles, `mcp-agent` and
   `bootstrap` in the map are startup errors.
10. **OIDC mode needs `APP_OIDC_ISSUER` and `APP_OIDC_AUDIENCE`** (or the
    `sso.*` config keys); startup fails and requests fail closed otherwise.
    `nbf` is now enforced (60 s skew).
11. **Reading `/audit` and `/audit/transparency/*` needs `audit.read`.** Grant
    it to custom roles that read the audit log; service-account, viewer,
    operator and `mcp-agent` are refused. The MCP `audit_query` tool is gone.
12. **Grant only what you hold.** Inviting or editing users, creating roles and
    minting API keys now require the caller to hold every permission of the role
    handed out; only an admin may grant pki-admin or bootstrap. Unknown role
    strings return 400. A delegate cannot demote or delete a user above its own
    grant.
13. **Cloud key inventory needs `key.manage` or `report.read`** (viewers and
    pki-viewers have it).
14. **Role changes from W20-27:** pki-operator can no longer write CAs,
    templates, targets, connectors, tenants or users; service-account and
    approver can no longer create CAs or connectors.
15. **User-store errors fail closed for login sessions.** Expect 503 on
    authz-check and refresh, and 401 elsewhere, during a user-database outage.
    The bootstrap token, API keys and externally issued bearer tokens are
    exempt.
16. **Login passwords are Argon2id.** Replace `APP_AUTH_LOGIN_PASSWORD_HASH`:
    `printf '%s\n' "$PASSWORD" | APP_AUTH_LOGIN_PASSWORD_PEPPER=... kryptkeeper --hash-password`.
    Legacy HMAC values still verify and are upgraded in memory only, with a
    warning in the log; the env value is yours to replace.
17. **Logout revokes the login session's refresh tokens** (the dashboard sends
    its refresh token in the optional logout body). Refresh re-reads the user's
    current role and status. The access token stays valid until it expires
    (`APP_AUTH_ACCESS_TTL_SEC`, default 900).
18. **Per-account login backoff.** Repeated failures delay logins for that
    account (up to 5 minutes at a time), with the same response for known and
    unknown emails.
19. **SAML IdP-initiated sign-in is refused** unless
    `APP_SAML_ALLOW_IDP_INITIATED=true`. The ACS needs an `InResponseTo` naming
    a request this process issued; in-memory state means sticky routing behind
    several replicas.
20. **OIDC first-login email linking needs `email_verified=true`.** An IdP that
    omits the claim needs accounts pre-linked by (issuer, sub). The browser that
    starts an OIDC login must be the one that finishes it (flow cookie).
21. **Session cookie `Secure` follows the connection.** It is set when the
    request is TLS or comes from a peer in `APP_TRUSTED_PROXY_CIDRS` that sends
    `X-Forwarded-Proto: https`. Behind a TLS-terminating proxy that is not
    listed, the cookie loses `Secure`; add the proxy.
22. **Security headers and `Cache-Control: no-store`** are added to every
    response and to `/api/`; the API itself is not framed (`frame-ancestors
    'none'`).
23. **Behind nginx or another proxy, set `APP_TRUSTED_PROXY_CIDRS`** to the
    proxy's address or subnet and restart. Without it every IP-keyed rate limit
    (login, refresh, SSO, ACME, OCSP, CRL, EST, SCEP, CMP, WSTEP, XCEP) buckets
    by the proxy and all users share one limit. The proxy must append to
    `X-Forwarded-For` (the shipped `nginx.conf` does).
24. **Request body caps return 413**: login, refresh and API-key create 16 KiB;
    agent register 16 KiB, renewal result 64 KiB, inventory 2 MiB; SCIM 1 MiB;
    pending-action proposals 64 KiB.

**Issuance and protocols**

25. **SSH certificates need a template `ssh_policy`.** Add one (cert types,
    exact allowed principals, host patterns, max TTL) to each template used for
    SSH, and send `template_id`. Without it, issuance is refused (400); a
    requested TTL over the template maximum is refused.
26. **ACME accepts only `dns` identifiers** that are valid names; wildcards need
    dns-01; `localhost` names, IP, URI and email identifiers are refused. The
    CSR must name exactly the order's identifiers. Single-label intranet names
    still work. RSA keys under 2048 bits are refused on ACME and CMP.
27. **CMP clients must send `transactionID` and a fresh `senderNonce`.** Set
    `KRYPTKEEPER_CMP_REFERENCE` so the `senderKID` is checked (empty only logs a
    warning), and `KRYPTKEEPER_CMP_ALLOWED_DNS_SUFFIXES` to bind issuable names.
    The replay cache is per process and in memory.
28. **OCSP:** a request for an issuer the hub does not serve returns
    `unauthorized`; a store failure returns `tryLater`. Responders or monitors
    that treated every answer as `good` will notice.
29. **Template name policy is enforced on every issuing path**, including
    renewal and bulk reissue. API issuance without a template is allowed and
    audited as having no name policy.
30. **Connector-pinned certificates renew upstream or fail.** If the pinned
    connector cannot be resolved the renewal fails rather than falling back to
    the hub CA.

**Network, plugins, cloud**

31. **Egress guard.** Webhook, Slack, PagerDuty, inventory-source, ACME
    connector and SIEM destinations on link-local, metadata, unspecified,
    multicast or loopback addresses are refused, and cross-host redirects are
    not followed. Private ranges remain reachable unless
    `KRYPTKEEPER_EGRESS_DENY_PRIVATE=true`.
32. **Discovery limits.** Scans over link-local targets, targets in
    `KRYPTKEEPER_DISCOVERY_DENY_CIDRS`, or expanding past
    `KRYPTKEEPER_DISCOVERY_MAX_TARGETS` (default 65536) return 400.
33. **SIEM settings (`SIEM_WEBHOOK_URL`, `SIEM_SYSLOG_ADDR`, `SIEM_FORMAT`) are
    read once at startup**; restart the hub after changing them. Forwarding is
    now active, so expect events at the sink.
34. **Plugins that run shells or interpreters with an inline command (`sh -c`,
    `python -c`), `sudo`/`doas`, `su`, `pkexec`, `runuser`, `setpriv` or `env`
    wrappers around them must declare `elevated_exec`.** Any plugin with
    a network capability, including `hosts_from_credential`, is High tier and
    needs a second admin's approval.
35. **MCP over HTTP needs `KRYPTKEEPER_MCP_HTTP_TOKEN`** (32+ characters) or the
    process will not start; set `KRYPTKEEPER_MCP_ALLOWED_HOSTS` and
    `KRYPTKEEPER_MCP_ALLOWED_ORIGINS` for non-loopback use. The stdio transport
    is unchanged.
36. **GCP and Azure CA keys are HSM-backed by default.** Opt down with
    `KRYPTKEEPER_GCP_KMS_PROTECTION=software` or `KRYPTKEEPER_AZURE_KEY_HSM=false`.
    New keys are tagged; scope IAM using `docs/ops/CLOUD_KMS.md`. Existing keys
    are untouched.
37. **The Kubernetes connector no longer skips TLS verification.**
    `KRYPTKEEPER_K8S_SKIP_VERIFY=true` is a startup error; set
    `KRYPTKEEPER_K8S_CA_CERT_FILE` (alias `KRYPTKEEPER_K8S_CA_FILE`).
38. **Console-run agents store their registration** in
    `KRYPTKEEPER_AGENT_CREDENTIALS_FILE` (default
    `<user config dir>/kryptkeeper-agent/credentials.env`, mode 0600).

**Deployment**

39. **Terraform:** `image_digest` (`sha256:<64 hex>`) replaces `image_tag`; the
    bootstrap token and keystore passphrase are no longer Terraform variables,
    so write them to Secrets Manager out of band (the instance refuses equal or
    empty values). The module now serves TLS (self-issued, or an operator
    certificate from Secrets Manager); plan for HTTPS to the instance.
40. **Helm:** probes, Service and ServiceMonitor follow `tls.enabled`; set
    `secrets.keystorePassphrase` and keep it different from the bootstrap token.

**Reports and features**

41. **Compliance results can change.** Certificates with unknown expiry now
    downgrade SOC2-CC6.7 from pass to warn, and evidence endpoints return 503
    when the CA list is unavailable. Key sizes are real (previously 0), so
    size-based posture flags and policy may fire on existing certificates.
42. **Finding exceptions are not available** and are hidden in the UI until
    v0.10.
43. **Multi-tenancy is experimental.** `MULTI_TENANCY` on refuses to start
    unless `KRYPTKEEPER_MULTI_TENANCY_EXPERIMENTAL=accept-risk`. Tenant
    isolation is not a security boundary in v0.9.
44. **Schema:** migrations `000070` (SSH certificate template id), `000071`
    (`verify_host_port`), `000072` (`auto_renew_set_by`), `000073`
    (`reissue_required` renewal status), `000074` (`minted_api_keys`),
    `000075` (CA status `pending_ceremony`) and `000076` (audit outcome and
    actor-type vocabulary, note 64) run on start; back up first. The schema
    version after upgrade is 76.
45. **Targets that were armed for hub-side auto-renewal go notify-only until
    re-armed.** The scheduler pushes a key only to an `auto_renew` target whose
    `auto_renew_set_by` names a principal that still exists and still holds
    `certificate.renew`. Rows from earlier builds have no such stamp, so the
    scheduler logs "NOT pushing ... notify-only" and sends the expiry reminder
    instead. To re-arm one, a pki-admin saves it again with
    `PATCH /api/v1/targets/{id}` and `{"auto_renew": true}` (pki-operator holds
    `certificate.renew` but not `discovery.manage`, so it gets 403 on
    `/targets`). A stamped principal who is deleted, deactivated or loses
    `certificate.renew` stops the push the same way (audit action
    `certificate.renew_execute_denied`). **Exception:** targets armed with an
    externally issued jwt or oidc bearer token carry a `token:` stamp that the
    hub cannot re-check, so a token principal who later loses its role keeps the
    target armed until it is saved again; arm targets with an API key or a login
    session instead. Principals of any other auth kind cannot arm a target at
    all (403).
46. **Arming key egress on a target needs `certificate.renew`.** Turning on
    `auto_renew`, naming a `credential_ref` or `plugin_id`, and (on an armed
    target) changing `host` or the install profile were `discovery.manage`
    actions; they now need `certificate.renew`, and `credential_ref` needs
    pki-admin. `credential_ref` and `plugin_id` must exist. Discovery-only roles
    keep everything else on targets.
47. **`POST /renewal/execute` and `/renewal/rollout` use the target's stored
    install profile.** A request-body `install` override is accepted from
    pki-admin only (403 otherwise). Callers that relied on sending the profile
    in the request must store it on the target (`install_server_type`,
    `install_cert_path`, `install_key_path`, `install_reload_method`,
    `verify_host_port`).
48. **`verify_host_port` may not be loopback or link-local**, and the hub's
    post-install verify dial refuses those addresses (including a name that
    resolves to one); private ranges stay allowed. Point it at an address the
    hub can reach on the network, or leave it empty for `<host>:443`. The agent
    still verifies its own server over loopback.
49. **`renewal_threshold_days` is limited to 1-365** (0 still means the process
    default). A hub-renewed certificate is never held to more than half its own
    lifetime, so a large value no longer renews it on every scan.
50. **Audit store default and format.** With `APP_AUDIT_PROVIDER` unset, a hub
    with a core database (any `APP_CERTIFICATE_PROVIDER=ca` install) now writes
    its audit trail to the database. This starts a new trail: events already in
    the file are not copied into the database and stay in the file. To keep one
    continuous file trail, set `APP_AUDIT_PROVIDER=file`. If you already set
    `file`, nothing switches: a legacy JSON-array file is converted to JSON
    Lines on first start (original kept as `<APP_AUDIT_FILE>.bak`); the file is
    now one JSON object per line, oldest first, so tools that parsed it as an
    array need updating. The DB audit store follows the core database (same
    DSN variables and driver); `APP_AUDIT_DB_DSN` overrides it. An unparseable legacy file, or any audit store that
    cannot be opened, stops the hub at start with a message naming the path.
51. **Memory sizing.** The Helm chart now requests 512Mi with a 2Gi limit and
    sets `GOMEMLIMIT` (`config.goMemLimit`, default `1600MiB`); Compose sets
    `mem_limit: 2g` and `GOMEMLIMIT=1600MiB`. Size up for estates above ~50k
    certificates (see "Memory sizing" in `docs/deployment.md`). Measured on
    `main` at `26e17cac` with 55k to 61k certificates and the SQLite CA provider
    (`docs/perf/rc3/README.md`, `docs/perf/rc3/03-measurements.md`): idle RSS
    629 to 665 MB, about 1.0 GB (964 to 1,066 MB) after the four report
    endpoints, a 970 MB peak during an 8-way issue burst, and about 11 KB of
    idle growth per certificate. The 2Gi limit therefore fits to roughly 100k
    certificates; that figure is an extrapolation, not a measurement. A 30-way
    bad-login spray raised RSS by about 325 MB (664 to 989 MB). Login hashing
    concurrency is capped; the Go runtime retains the freed buffers, so this is
    an RSS high-water mark, not unbounded growth; `GOMEMLIMIT` is a soft limit that makes the Go runtime
    collect harder as RSS approaches it, so set it together with the container
    limit.
52. **Client IP behind the bundled nginx.** Compose pins its network and sets
    `APP_TRUSTED_PROXY_CIDRS` to the dashboard's address so rate limits and
    audit source IPs are per client. If you run your own proxy, set it to that
    proxy's address (never a whole subnet the public can reach). The Helm chart
    leaves `config.trustedProxyCIDRs` empty and warns when an ingress is used.
53. **New renewal status value.** `renewal_status` can now be
    `reissue_required` (set by the CA-key compromise flow). API clients that
    switch on the four previous values should handle it.
54. **Core-database failure is now fatal with the `ca` provider.** If the core
    database cannot be opened or migrated, the hub exits with the error instead
    of logging a warning and running with an in-memory CA. A data directory
    that was first used with another provider (for example the default when
    `APP_CERTIFICATE_PROVIDER` is unset) now migrates cleanly when you switch
    to `ca`: migrations `000020`, `000023`, `000024`, `000032`, `000047`,
    `000057` and `000059` tolerate columns a store already added, and from
    rc.5 any purely additive migration is tolerated automatically (the log
    says `statement already satisfied, skipping`). Fix the database error
    rather than expecting the hub to start without it.
55. **Keystore directory default.** If `KRYPTKEEPER_DATA_DIR` is set and
    `KRYPTKEEPER_KEYSTORE_DIR` is not, keys are stored in
    `<KRYPTKEEPER_DATA_DIR>/keys`. A `./var/keys` directory that already holds
    keys is still used, with a warning; move the keys and set
    `KRYPTKEEPER_KEYSTORE_DIR` explicitly to silence it. The hub logs the
    resolved path at startup and refuses to start if it is not writable.
56. **API keys are persisted.** Keys minted with `POST /api/v1/api-keys` are
    stored in the core database and survive restarts. With no core database
    they remain memory-only and the hub warns at startup. Keys declared in
    `APP_API_KEYS_JSON` are unchanged and win on a key-id collision. Migration
    `000074` adds the `minted_api_keys` table (verifier only, never the secret).
    `POST` returns 503 if the key cannot be saved (no key is issued);
    `DELETE` returns 503 if the revocation is not yet durable (the key is
    already rejected; repeat until 204).
57. **Re-mint API keys once.** Keys minted through the API on earlier builds
    (including rc.1 and rc.2) were held in memory and lost at every restart, so
    any you rely on today only works until the next restart. After upgrading,
    mint them again, or move them to `APP_API_KEYS_JSON`.
58. **Missing CA keys at startup are fatal.** If an active CA has no usable key
    in the keystore (`KRYPTKEEPER_KEYSTORE_DIR` or `KRYPTKEEPER_DATA_DIR`
    changed, volume not mounted, wrong passphrase), the hub refuses to start
    and names the CA and key id; before, it ran and returned 503 on issuance
    with empty CRL/OCSP. Point it back at the right keystore. For a deliberate
    recovery only, set `KRYPTKEEPER_ALLOW_MISSING_CA_KEYS=true` to start anyway
    (those CAs cannot issue or sign CRL/OCSP). A key that is present but does
    not match its certificate is still only logged.
59. **Notification rules now send; existing rules start alerting.** Under
    `APP_NOTIFICATION_PROVIDER=delivery` (the Compose default) rules created
    earlier were not stored, so they never fired. Rules are now persisted and
    evaluated. Review the rules and their targets before upgrading; new rules
    are validated (400 on bad input).
60. **Template `validity_period` is now applied.** A template with `P1Y` now
    issues 1-year certificates (clamped to the CA's `NotAfter`; short-lived
    templates cap at 7 days); every ISO-valued template used to issue 90-day
    certificates. Check templates before upgrading. A template whose period
    cannot be parsed now fails issuance, and creating one is rejected.
61. **Postgres ids are UUIDs** for users and notification deliveries. Clients
    should not assume the non-UUID id formats a SQLite hub issues
    (`notif-...`, `retry-...`) on PostgreSQL.
62. **Root-CA ceremonies now work.** A root created through a key ceremony stays
    `pending_ceremony` until approved instead of going active unapproved.
    Migration `000075` is required (note 44).
63. **Migration `000076` rebuilds `audit_log`; its down refuses.** On SQLite
    the table is rebuilt in one transaction (rows, ids, indexes and the
    append-only triggers are preserved); on PostgreSQL the `outcome` column
    becomes `VARCHAR(32)` and both CHECK constraints are swapped, with no row
    touched. Back up first. The down migration refuses to run, and changes
    nothing, while any row exists with an outcome or actor type that only the
    new vocabulary allows (the audit log is append-only, so it never deletes or
    rewrites them); rolling back therefore needs a restore, not `down`. An audit
    store on its own DSN (`APP_AUDIT_DB_DSN`) never runs core migrations, so it
    widens a table that predates the new CHECKs when it opens.
64. **Audit rows were silently lost in release candidates 1 to 6.**
    `audit_log` only accepted the outcomes `success`, `failure` and `denied` and
    the actor types `user`, `api_key`, `system` and `agent`. The hub also
    records `skipped` (a notification alert not delivered), `pending_approval`
    (certificate issue or renewal held for approval), `proposed` (a dual-control
    key rotate, delete or export), `executed` (an approved pending action),
    `issuance_failed` (an approval whose issuance failed) and `partial`, and
    SPIFFE workload attestation writes actor type `workload`. With the database
    as the default audit store (the default from rc.2; opt-in on rc.1 with
    `APP_AUDIT_PROVIDER=db`), every such append failed its CHECK and was only
    logged and counted in `kryptkeeper_audit_append_failures_total`: the event
    was never stored. The file audit store was not affected. No released
    version is affected, because 0.9.0 is the first public release; if you ran
    an rc build on the database audit store, rows for those events from before
    rc.7 do not exist and cannot be reconstructed. From this build they are
    stored and the counter should stay at zero.
65. **`certificate.renew_execute` with an unverified install is now outcome
    `partial`.** It used to record the open-ended outcome
    `renewed_install_<x>`; the install result is now in the `change_summary` as
    `install_outcome=<x>`. Anything that filters audit rows or SIEM events on
    `renewed_install_*` needs updating. SIEM severity treats `partial` and
    `issuance_failed` as adverse, like `failure` and `denied`.
66. **`GET /api/v1/audit?outcome=` now filters.** It was ignored, so the Audit
    page's outcome dropdown never narrowed anything. It accepts any of
    `success`, `failure`, `denied`, `skipped`, `pending_approval`, `proposed`,
    `executed`, `issuance_failed`, `partial` and answers 400 for any other
    value. The UI Audit filter lists all of them.
67. **Providers that do not deliver no longer record alerts as sent.** With
    `APP_NOTIFICATION_PROVIDER=file` or `db` (they only record), the renewal
    scheduler skips notification-rule alerts and owner reminders: no cooldown is
    written, the audit row `renewal_notification_sent` has outcome `skipped`
    with the reason (at most once per certificate and rule, and once per
    certificate for the owner reminder, every 24 hours; a restart audits again), a per-tick
    summary is logged, and a startup WARNING appears when rules exist.
    `POST /api/v1/notifications/test-delivery` answers `dispatched=false` with a
    note. Set `APP_NOTIFICATION_PROVIDER=delivery` to send. Before, those
    providers marked the alert sent, so an expiring certificate was reported as
    notified when nothing left the hub.
68. **Notification rule alerts are rate-bounded.** One scan processes at most
    `KRYPTKEEPER_RENEWAL_RULE_SEND_CAP` rule alerts (default 500; the rest roll
    to the next scan, and skips do not consume the budget). Delivery sends use a
    pool of 8 workers behind a 1024-deep queue, and the in-memory delivery log
    keeps the newest 10,000 entries.
69. **Template `validity_period` is limited to 100 years in total.** Longer
    values, including several large components that used to overflow and wrap
    to a short positive period, are rejected at create and fail issuance. The
    issuing CA's `NotAfter` still clamps the result.
70. **A CA key-consistency check that cannot run is fatal.** If the startup
    check of CA keys against their certificates returns an error (not only a
    missing key, note 58), the hub refuses to start unless
    `KRYPTKEEPER_ALLOW_MISSING_CA_KEYS=true`.

### Notes

- A handful of UAT scenarios remain blocked on hardware/accounts not
  available in this environment (Active Directory, F5/Citrix devices,
  cloud KMS accounts) — tracked as `blocked` in
  [`docs/UAT_PLAN.md`](docs/UAT_PLAN.md), not shipped as `done`.
- Beta, experimental and not-in-v0.9 features are listed in the README under
  "Status of features in v0.9"; per-feature evidence is in
  [`docs/release/FEATURE_VALIDATION_v0.9.md`](docs/release/FEATURE_VALIDATION_v0.9.md).

---

## Internal milestones (before the first public release)

The sections below were internal milestones and were never released
publicly. Their git tags are now `internal/vX.Y.Z`.

### internal/v2.2.0 — 2026-06-18 — Multi-Tenancy

Tenant isolation as policy folders. Every CA, certificate, template, approval,
and AI proposal belongs to exactly one tenant; principals see only their own.
Flag-gated and **off by default** (`MULTI_TENANCY=on`), so existing single-tenant
deployments are unchanged until they opt in. Scope: `docs/v2.2_MULTI_TENANCY_SCOPE.md`.

#### Added

- **Tenant model** (W1): `tenants` + `ca_tenants` tables (migration `000019`),
  super-admin tenant CRUD (`/api/v1/tenants`) and CA→tenant mapping. Principals
  carry a resolved `Tenant` and `SuperAdmin`; CA lists filter by tenant
  (deny-by-default on lookup failure).
- **Issuance-surface scoping** (W2, migration `000020`): certificates and
  approval requests inherit their issuing CA's tenant; templates use an explicit
  `template_tenants` mapping (unmapped = shared/default catalog); the AI proposal
  queue stamps the proposer's tenant on each row (so a failed lookup can never
  leak the queue, and cross-tenant approval is impossible — approve/reject hides
  other tenants' actions as 404).
- **Management UI + view-as** (W3): a Tenants page (tenant CRUD + CA/template
  assignment), a sidebar tenant switcher, and `GET /api/v1/tenants/context`.
  A super-admin can "view-as" a tenant (`X-Tenant` header) to see exactly what
  that tenant sees, while retaining full identity for administration.

#### Configuration

- `MULTI_TENANCY` (default off). When off, every principal is a super-admin in
  the `default` tenant and no filtering is applied — identical to single-tenant.

#### Notes

- Tenant assignment for principals is via the `X-Tenant` header (and bootstrap =
  super-admin) in this release; a JWT/OIDC tenant claim is a follow-up. The next
  major candidates are v2.1.x (gRPC SPIFFE Workload API + attestation) and v2.3.

---

### internal/v2.1.0 — 2026-06-18 — SPIFFE/SVID Workload Identity

Short-lived cryptographic identity for workloads. Design:
`docs/v2.1_SPIFFE_SCOPE.md`, guide: `docs/guides/spiffe.md`.

#### Added

- **URI SAN support** in the CA engine and issuance (`ca.IssuanceRequest.URIs`,
  with CSR fallback); surfaced as `uri_sans` on certificates and in the cert
  detail panel. Foundational for SPIFFE (SPIFFE IDs are `spiffe://` URI SANs)
  and useful generally.
- **SVID issuance**: `POST /api/v1/spiffe/svid` mints a short-lived SVID for a
  `spiffe://<trust-domain>/<workload>` ID (generates the keypair, issues with
  the SPIFFE ID as the URI SAN and client+server auth EKU), returning the cert,
  key, and trust bundle. Trust-domain mismatch is rejected; minting is gated to
  admin/operator roles.
- **Trust bundle**: `GET /api/v1/spiffe/bundle` serves the trust domain's CA
  chain as PEM.
- **SPIFFE dashboard**: trust-domain status, a mint form, and an issued-SVID
  inventory.

#### Configuration

- `SPIFFE_TRUST_DOMAIN`, `SPIFFE_SIGNING_CA_ID`, `SPIFFE_SVID_TTL` (default 1h).
  Requires the CA engine; disabled (and reported as such) until configured.

#### Notes

- This is a REST mint + bundle. The gRPC SPIFFE Workload API and node/workload
  attestation are a planned v2.1.x release. Multi-tenancy is v2.2.

---

### internal/v2.0.0 — 2026-06-18 — AI-Native PKI Operations

Agentic PKI ops with the guardrail built in. An AI assistant can read the full
posture and *propose* changes — but every write routes through the approval
queue: the AI proposes, a human approves, the audit log records both. No other
PKI does this. Design: `docs/v2.0_AI_NATIVE_SCOPE.md`,
guide: `docs/guides/mcp-server.md`.

#### Added

- **MCP server** (`kryptkeeper-mcp`): a Model Context Protocol server (stdio)
  exposing Kryptkeeper to AI assistants. A thin adapter — each tool maps to an
  authenticated Hub REST call, so auth, RBAC, and audit apply unchanged.
  - **Read tools** (11): list_certificates, get_certificate, search,
    crypto_posture, pqc_migration, pqc_countdown, renewal_slo,
    compliance_evidence, list_cas, ca_health, audit_query.
  - **Write tools** (proposal-only): propose_revoke, propose_bulk_revoke
    ("everything a compromised CA signed"), list_pending_actions. These create
    a pending action for human approval and **never mutate directly**.
- **Generalized approval queue** (`pending_actions`, migration 000018): a human
  approves a proposed action and the Hub then executes it; approval is gated to
  approver roles and forbids self-approval (proposer ≠ approver). A new
  **Pending Actions** dashboard page surfaces AI-proposed changes with rationale.

#### Notes

- MCP transport is stdio (Claude Desktop / local clients); streamable HTTP is a
  follow-up. SPIFFE/SVID (v2.1) and multi-tenancy (v2.2) are separate releases.

---

### internal/v1.5.0 — 2026-06-18 — PQC Migration Copilot

The migration *journey* nobody else has: classify exposure, plan waves, execute
hybrid rollout, and prove progress against the 2030/2031 deadlines — trending
over time. Design: `docs/v1.5_PQC_COPILOT_SCOPE.md`.

#### Added

- **PQC migration roadmap**: `GET /api/v1/reports/pqc-migration` — a prioritized
  plan (CA and code-signing trust anchors flagged critical; long-lived classical
  = harvest-now-decrypt-later; SAN sprawl noted). New **PQC Migration** page.
- **Migration waves**: vulnerable certs auto-grouped into Test → Internal →
  Customer-facing tracked sets (from naming, SANs, labels) with owners and live
  progress; editable. `migration_waves` (migration 000017). Auto-derive +
  per-wave progress bars on the PQC page.
- **CNSA 2.0 / NIST 800-131A countdown**: `GET /api/v1/reports/pqc-countdown`
  (JSON + branded PDF) — readiness, days-remaining to each deadline, migration
  status, per-wave progress, and the PQC-readiness trend (from daily posture
  snapshots). The board-ready proof-of-progress artifact.

#### Notes

- Migration status is tracked (a cert counts migrated once it's no longer a
  vulnerable classical cert); a one-click "migrate now" re-issue is a follow-up.

---

### internal/v1.4.0 — 2026-06-17 — Audit-Ready Evidence Packs

The "my auditor loved it" release. Hand an auditor a branded PDF that maps their
framework's controls to live certificate posture — instead of screenshotting
dashboards. Design: `docs/v1.4_AUDIT_READY_SCOPE.md`.

#### Added

- **Compliance evidence pack (PDF)**: `GET /api/v1/reports/compliance-evidence?format=pdf`
  renders a branded, per-framework pack (PCI DSS 4.0.1, SOC 2, NIST SP 800-57)
  with status-colored controls, evidence, and remediation. Pure-Go rendering
  (go-pdf/fpdf) — no browser/CGO dependency. Download button on the Compliance
  Evidence page.
- **Executive one-pager (PDF)**: `GET /api/v1/reports/executive-summary` (JSON
  tile / PDF) — a board-readable summary of posture, automation, compliance,
  and risk with headline actions. Download in the Dashboard hero.
- **Scheduled email delivery**: recurring evidence packs emailed to auditors on
  a weekly/monthly cadence, plus ad-hoc "Send now". DB-backed schedules
  (`evidence_schedules`, migration 000016) editable on the Settings page. Real
  MIME email with PDF attachment via SMTP (opt-in: set `SMTP_HOST`/`SMTP_FROM`).

#### Configuration

- `KRYPTKEEPER_ORG_NAME` — organization name printed on evidence packs.
- `SMTP_HOST` / `SMTP_PORT` / `SMTP_FROM` / `SMTP_USERNAME` / `SMTP_PASSWORD` —
  email delivery (delivery stays disabled until configured).
- `EVIDENCE_POLL_HOURS` — scheduler cadence check interval (default 6).

---

### internal/v1.3.1 — 2026-06-17 — Agent persistence

Hardening for Renewal Autopilot: the Hub's agent registry is now restart-safe.

#### Added

- **DB-backed agent store** (SQLite/Postgres): agent registrations, inventory,
  endpoints, renewal tasks, and results persist across Hub restarts. Previously
  in-memory — a restart wiped agent identities, pending tasks, and SLO/audit
  history. Migration `000015`; the store self-applies its schema idempotently.
  Falls back to in-memory when no DB is configured.

#### Changed

- The agent store is now an interface with in-memory and DB-backed
  implementations sharing one cert→endpoint assignment function.

#### Known limitations

- Agent tokens are stored as-is; hashing at rest is a planned follow-up.

---

### internal/v1.3.0 — 2026-06-17 — Renewal Autopilot

Closes the discover → issue → **install** → **verify** loop. The satellite
agent now renews certs, installs them where the web server reads them, reloads,
and confirms the new cert is actually being served — and the Hub drives it all
automatically. Nobody in OSS closes this loop. Design:
`docs/v1.3_RENEWAL_AUTOPILOT_SCOPE.md`.

#### Added

- **Endpoint discovery**: the agent parses nginx `server {}` and Apache
  `<VirtualHost>` blocks into installable endpoints (cert path, key path, server
  type, server name, listen port) and reports them in its inventory.
- **Cert installer**: backup → atomic write → config validation
  (`nginx -t` / `apachectl configtest`) → reload, with automatic **rollback**
  (restore + reload) on validation or reload failure. A bad cert can never take
  a site down. Reload auto-detects systemctl vs the server binary.
- **Verify-after-install**: after reload, the agent TLS-dials the endpoint and
  confirms the served leaf matches the renewed fingerprint; mismatch rolls back.
  A renewal is "done" only when verified.
- **Result reporting**: `POST /api/v1/agent/renewal-result`; the agent reports
  install/verify outcomes back to the Hub for audit and SLO.
- **Task assignment**: the Hub matches expiring auto-renewable certs to reported
  endpoints (by cert path) and issues install-hinted renewal tasks — the loop
  runs with no manual wiring. Failures auto-retry; successes clear.
- **Renewal SLO + Automation page**: `GET /api/v1/reports/renewal-slo`
  (success rate, mean time to renew, endpoints managed, agents, failed-renewal
  queue) on a new dashboard Automation page. The renewal-scheduler status panel
  moved here from Settings.
- **Privilege model**: `kryptkeeper-agent --generate-sudoers` emits a narrow
  sudo allowlist (install, `nginx -t`, reload only). Autopilot is opt-in —
  enabling it requires the drop-in and relaxing the unit's `NoNewPrivileges`.

#### Fixed

- The renewal scheduler (built in Sprint 5) was never started — now wired into
  Hub startup. (Carried from the v1.2 fix; reaffirmed as the autopilot trigger.)

#### Known limitations

- The Hub agent registry is in-memory; agent tasks/results/endpoints do not
  survive a Hub restart. Persistence is planned for a v1.3.x hardening release.
- Apache install is implemented but not yet validated end-to-end on a real host.
- The failed-renewal queue is informational; failures auto-retry on the next
  inventory cycle (no manual retry button yet).

---

### internal/v1.2.0 — 2026-06-16 — Visibility Sprint

Makes shipped backend capability visible and operable. Theme: *nothing counts
until a user can see it, click it, and show it to an auditor*
(`docs/archive/GO_FORWARD_PLAN.md` §5). Design notes: `docs/v1.2_VISIBILITY_SPRINT.md`.

#### Added

- **Posture snapshots + trend chart**: daily crypto-posture snapshot
  (`posture_snapshots`, migration 000014) feeding a trend chart (PQC score %,
  automation %) on the Crypto Posture page; `GET /api/v1/reports/crypto-posture/trend`. Foundation for v1.5 PQC-migration progress proof.
- **Ownership editing UI**: owner email/team, service, labels editable on the
  certificate detail panel (previously API-only).
- **Renewal scheduler status panel**: scheduler now records each scan
  (candidates, auto-renew triggers, notifications, expired-skipped, last/next
  run); `GET /api/v1/scheduler/renewal/status` surfaced on a new Settings page.
- **SIEM integration panel**: status (masked targets) + "Send test event" with
  per-target results on Settings; `GET /api/v1/integrations/siem`,
  `POST /api/v1/integrations/siem/test`.
- **Code-signing inventory**: derived live from the certificate inventory (EKU
  includes codeSigning); `GET /api/v1/inventory/code-signing` + Code Signing
  page under Operations.

#### Fixed

- **Renewal scheduler was never started.** It was fully built in Sprint 5 but
  no `.Start()` call existed in `main.go` — it was dead code. Now wired into
  server startup alongside the new posture-snapshot scheduler.

#### Deferred

- **SSH-key inventory**: `internal/sshkeys` exists but has no data source (no
  discovery populates it). Deferred until SSH discovery is built — likely
  alongside v1.3 host agents. See `docs/v1.2_VISIBILITY_SPRINT.md`.

---

### internal/v1.1.0 — 2026-06-10

Sprints 5 and 6: security foundations, key management, and advanced automation.
Closes the top compliance gaps from `docs/STRATEGIC_GAP_ANALYSIS.md`.

#### Added

**Compliance & Audit (Sprint 5)**
- Audit log now records `source_ip`, `user_agent`, `session_id`, and `change_summary` on every event (SOC 2 / PCI DSS / FedRAMP evidence)
- Risk scoring expanded from 3 to 11 signals: weak RSA/EC key sizes, validity >397d and >200d, self-signed, wildcard SAN, missing OCSP URL, missing CRL distribution point
- Certificate ownership: `owner_email`, `owner_team`, `service_name`, `labels` on every certificate + `PATCH /api/v1/certificates/{fp}/ownership`
- Seven new reports: CA Health, Expiry Timeline, Revocation Activity, Issuance Velocity, Change Audit, Compliance Evidence Pack, Algorithm Sunset (RSA-2048/ECC-224 post-2030 non-compliance)

**Renewal Automation (Sprint 5)**
- Hub-side renewal scheduler: daily scan for approaching expiry, owner notifications, audit-logged
- ACME Renewal Information (ARI, draft-ietf-acme-ari): `GET /acme/renewalInfo/{certID}` with staggered renewal windows — required for the CA/B Forum 47-day certificate timeline

**SIEM Integration (Sprint 5)**
- Webhook push and RFC 5424 syslog output for certificate lifecycle events (`SIEM_WEBHOOK_URL`, `SIEM_SYSLOG_ADDR`)

**Key Management (Sprint 6)**
- HashiCorp Vault transit backend: software keys wrapped by a Vault-managed master key (`APP_KEYSTORE_TYPE=vault`); keys non-extractable by design
- Key rotation API: `POST /api/v1/keys/{id}/rotate` with optional algorithm change
- Key backup and disaster recovery: passphrase-wrapped export (`POST /api/v1/keys/{id}/export`) and import (`POST /api/v1/keys/import`)
- Signer cache TTL eviction: decrypted CA signers evicted after idle timeout (default 60 min, `KEYSTORE_SIGNER_TTL_MINUTES`)
- Azure Key Vault RSA fix: RSA JWK parsing implemented — Azure RSA CA keys now work

**Issuance Workflow (Sprint 6)**
- Approval workflow: templates can set `require_approval` + `approval_roles`; pending requests managed via `/api/v1/approvals` (list, approve, reject)
- Bulk operations: `POST /api/v1/certificates/bulk-revoke` (500/request) and `/bulk-reissue` (200/request) for incident response
- Short-lived certificate profiles: ≤7-day certs, OCSP-exempt per CA/B Forum carve-out

**Dashboard**
- Full UI redesign: sidebar navigation, command palette, skeleton loaders, command-center dashboard
- 8 new pages including all report views and agent management

#### Fixed
- Bootstrap auth mode now validates login-session JWTs from cookies
- CA IDs are UUID v4 (PostgreSQL UUID column compatibility)
- Dockerfile base image bumped to `golang:1.25-alpine` to match go.mod
- Docker ports bind to all interfaces; `KRYPTKEEPER_DATA_DIR` passed to container
- JWT stored in sessionStorage as Bearer fallback for IP-origin logins

#### Security
- Runtime data directories (`var/`) removed from version control and gitignored — encrypted dev CA key artifacts are no longer tracked

---

### internal/v1.0.0 — 2026-04-25

#### Added

**Post-Quantum Cryptography (NIST FIPS 203/204/205)**
- ML-DSA-44, ML-DSA-65, ML-DSA-87 key generation and issuance via Cloudflare CIRCL
- Hybrid certificates: ECDSA + ML-DSA alt-sig extension (X.509 composite pattern)
- PQC readiness score on Crypto Posture dashboard

**Certificate Authority Engine**
- Root and intermediate CA creation (RSA-2048/4096, ECDSA-P256/384, ML-DSA)
- OCSP responder and CRL distribution point (RFC 6960, RFC 5280)
- Template policy enforcement at issuance: algorithm allow-list, max validity, EKU, min key size
- HTTP 422 with structured error on policy violation

**Enrollment Protocols**
- ACME (RFC 8555): HTTP-01 and DNS-01 challenges, auto-renewal
- SCEP: Intune BYOCA support via `/scep/mscep_admin` NDES-compatible endpoint
- EST (RFC 7030): simple enroll + re-enroll
- CMP (RFC 4210): proper ASN.1 codec
- WSTEP/XCEP: Windows GPO-based autoenrollment with template lookup
- Microsoft Integration Status API (`GET /api/v1/integrations/microsoft`)

**HSM / PKCS#11**
- Build-tag-guarded PKCS#11 backend via `github.com/ThalesGroup/crypto11`
- `KRYPTKEEPER_KEY_BACKEND=pkcs11` env var switches at runtime
- Software store (default) unaffected

**Satellite Agent**
- `kryptkeeper-agent` binary: outbound-only, <15 MB, no CGO on non-Windows builds
- Linux filesystem cert discovery (walks `/etc/ssl`, `/etc/pki`, nginx/Apache paths)
- Web server config parser: nginx `ssl_certificate`, Apache `SSLCertificateFile`, HAProxy `crt`
- Windows certificate store discovery via Win32 `CertEnumCertificatesInStore` (build-tag guarded)
- ACME renewal executor: HTTP-01 challenge via webroot or in-process listener
- Hub API: `POST /api/v1/agent/register|heartbeat|inventory`, `GET /api/v1/agent/tasks`
- `--generate-systemd` flag prints a hardened systemd unit file
- Cross-compiled: linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64

**Ecosystem Integrations**
- cert-manager external issuer: `CertificateRequest` → Kryptkeeper → patch status
  (no controller-runtime dependency; raw Kubernetes API over HTTP)
- Terraform provider (`registry.terraform.io/kryptkeeper/kryptkeeper`):
  `kryptkeeper_ca`, `kryptkeeper_certificate`, `kryptkeeper_template` resources

**Observability & Reporting**
- Crypto Posture dashboard: algorithm breakdown, PQC readiness %, expiry buckets (47d/90d/200d/1yr)
- Grade distribution (A–F), automation coverage %, risk breakdown (critical/high/medium/low)
- CSV export (`?format=csv`) for SIEM ingestion

**Cloud Inventory**
- AWS ACM, Azure Key Vault, GCP Certificate Manager connectors
- Kubernetes cert-manager connector

**Discovery**
- Network scanner: TLS fingerprinting, port sweep, cert metadata extraction
- Scan history and certificate detail panel

**Authentication & RBAC**
- JWT + API key authentication, multi-user support
- Bootstrap token mode for initial setup

**Infrastructure**
- SQLite (default) and PostgreSQL database backends
- Helm chart for Kubernetes deployment (`charts/kryptkeeper/`)
- cert-manager issuer Helm chart (`charts/kryptkeeper-certmanager-issuer/`)
- Docker multi-arch image (linux/amd64, linux/arm64)

#### Security

- All endpoints require authentication; unauthenticated requests return 401
- Private key bytes never leave HSM in PKCS#11 mode
- Agent tokens are 32-byte cryptographically random hex values
- Template policy enforcement prevents issuance outside approved parameters
- Systemd unit hardening: `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`

#### Test Coverage

- 523 tests across 25 packages (main module)
- 7 tests in terraform-provider-kryptkeeper module
- All enrollment protocols covered: ACME, SCEP, EST, CMP, WSTEP, XCEP
- Policy enforcement, hybrid certs, PQC issuance, PKCS#11 stub all tested

---

### Pre-release build — 2026-04-24 (no tag)

Initial internal release covering CA engine, OCSP/CRL, all 5 enrollment protocols,
cloud inventory connectors, Kubernetes cert-manager integration, and Helm chart.
See `docs/IMPROVEMENT_PLAN_V2.md` for the full wave-by-wave history.
