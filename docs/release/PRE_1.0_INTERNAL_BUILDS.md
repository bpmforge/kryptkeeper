# Pre-1.0 internal builds (v0.10.0 to v0.21.0)

These builds were tagged only in the private development repository. They were never published. Version 1.0.0 is the first public release, and it contains all of this work. The summaries below record what each internal build added, so the history behind 1.0.0 is not lost. See [CHANGELOG.md](../../CHANGELOG.md) for the public release history.

## v0.10.0

Released 2026-10-16.

- Multi-tenancy became an isolation boundary. All 21 cross-tenant leaks found in live validation were fixed, each with a named regression test.
- Governance: approvals with expiry, n-of-m quorum and dated delegation; issuance policy administration with dry-run, version history and revert; risk exceptions behind the approval queue.
- Ownership tracking, access review reports, recertification campaigns and a Roles page with separation-of-duties checks.
- Break-glass accounts with two-person activation and 4-hour windows.
- Audit: offline verification with `kryptkeeper-audit-verify`, tenant-scoped export, and a signed retention archive under dual control.
- Upgrade notes: a baseline issuance policy is created if none exists, and unmapped SSO users are now denied.

## v0.11.0

Released 2026-10-16.

- A 9-algorithm CA matrix, including ML-DSA-44/65/87, with per-CA key backends.
- External and offline roots, cross-signed key rollover with rollback, and CA revocation.
- Key compromise handling that rotates, revokes and re-issues, and template enrollment permissions with revision history.
- Revocation at scale: database-backed CRL numbers, delta CRLs and CRL shards.
- Two-replica high availability that fails closed when the shared database is lost.
- Fixes for OCSP GET requests containing `/`, ML-DSA KeyUsage bit order and missing AuthorityKeyIdentifier on cross-sign bridges.

## v0.12.0

Released 2026-10-16.

- Discovery: per-target scan schedules, agentless SSH discovery with pinned host keys, and scan-diff events such as `CERTIFICATE_REPLACED` and `KEY_DOWNGRADE`.
- Certificate Transparency findings you can list, acknowledge and act on.
- Multi-account cloud and multi-cluster Kubernetes discovery.
- Bulk takeover of the discovered estate and an estate board report.
- Template migration from ADCS, Vault, Venafi, Keyfactor and DigiCert CertCentral, with dry-run, approval-gated apply and undo.
- The agent poll default changed from 300 s to 60 s.

## v0.13.0

Released 2026-10-16.

- Deployment: a prebuilt dashboard image, Helm high availability by default (2 replicas and a PodDisruptionBudget), and the `kryptkeeper migrate status|down` commands.
- Scripted SQLite backup and restore.
- A cosign-signed air-gap bundle, signed apt and yum repositories, a two-arch Homebrew formula and a signed `install.sh`.
- CI gates for licences (no GPL, AGPL or SSPL) and for Terraform.
- Fix: replicas now see each other's certificates. Postgres connection use per replica was also reduced.

## v0.14.0

Released 2026-10-16.

- Enrollment credentials for ACME, EST, CMP and SCEP are managed through the API and UI instead of env files.
- ACME: EAB key API, provisioners with domain allow-lists, ARI support, and renewal windows with backoff on the upstream side.
- SCEP renewal, CMP revocation and polling, and SSH issuance that honours approval templates.
- A code-signing profile with mandatory approval and YubiKey PIV attestation support.
- Fix: the cert-manager issuer now works on a real cluster, and the Terraform provider sends correct CA fields.
- Upgrade note: EST now answers 401, not 403, for unauthenticated clients.

## v0.15.0

Released 2026-10-16.

- Auto-renew follows explicit certificate-to-target bindings, not host names. A one-time backfill converts existing matches.
- A durable failure queue with retry, per-connector throttling, a worker pool and a drain on shutdown.
- ACME dns-01 for Route53, Azure DNS, GCP DNS, RFC 2136 and CNAME delegation, plus fleet http-01.
- DigiCert, SCEP, EST and WSTEP as connector types, and a Tomcat installer.
- Cluster-atomic rollout groups for nginx, Apache and HAProxy over SSH.
- Delivery plugins for Vault KV, Azure Key Vault, GCP Secret Manager, AWS, Azure and Cloudflare. A 2,000-certificate renewal storm test only partly passed; the build records that gap.

## v0.16.0

Released 2026-10-17.

- Compliance reporting: a published risk-score formula, posture history with a compare-two-dates view, and scheduled report delivery as CSV, XLSX or PDF.
- Evidence packs gained FedRAMP Moderate control mappings (mappings only), a control-to-artifact index, a key-custody section and manual attestations.
- A validated CycloneDX 1.6 CBOM and key-custody entries showing requester, approver and redeemer.
- CSV exports escape formula-injection prefixes.
- Drill-through links from operations pages to filtered lists.
- The external auditor dry run had not happened for this build.

## v0.17.0

Released 2026-10-17.

- A SPIFFE Workload API conformance harness and guide.
- Non-human identity revocation, a management page for non-human identities, and single-use agent enrollment tokens.
- MCP agent surface: blast-radius impact on proposals, a `blast_radius` tool and a tool catalogue page.
- Short-lived code-signing certificates bound to CI OIDC tokens (GitHub and GitLab claim sets).
- An RFC 3161 time-stamp service, closed by default.
- Known gap: the non-human identity request-time authorizer was not wired to any request path.

## v0.18.0

Released 2026-10-17.

- Alerting: expiry thresholds as a percent of lifetime, owner-team routing and channels that reload at runtime.
- SLO error budgets with 1 h and 6 h burn rates, and an SLO dashboard page.
- Anomaly findings that create propose-only remediations in the approval queue.
- Natural-language policy drafting, with drafts landing disabled behind an approval. There is no LLM front end.
- Structured JSON logging, health and metrics endpoints for every process, and live operation events over SSE.
- At 100k certificates on Postgres, search p99 fell from 975 ms to 115 ms.

## v0.19.0

Released 2026-10-17.

- Post-quantum agility: readiness labels that can get worse but never better, and ML-DSA signed CRL and OCSP.
- FIPS, allow-list and HSM refusals on PQC issuance.
- PQC migration waves with verify and rollback, and non-PQC transitions such as RSA-2048 to ECDSA-P384 through the same waves.
- A blast-radius page and `GET /api/v1/blast-radius`.
- A statement that ML-DSA and hybrid keys are software-keystore only.
- Production PQC delivery was still manual, and OpenSSL 3.5+ interop passed.

## v0.20.0

Released 2026-10-17.

- The OpenAPI spec is served by the hub, and Go, TypeScript and Python SDKs are generated in the release workflow.
- Terraform provider data sources and acceptance tests.
- Signed outgoing webhooks (HMAC-SHA256) with secret rotation.
- An ITSM framework with ServiceNow and Jira connectors, and CMDB ownership sync.
- Slack and Teams interactive approvals, with the acting channel recorded in the audit log.
- Several validation runs were left to human operators: F5 and Citrix plugins, ServiceNow and Jira, and the contributor dry run.

## v0.21.0

Released 2026-10-17.

- A Playwright browser harness with journeys for first run, role matrix and adding targets.
- Onboarding and config improvements, and break-glass protection for SSO overrides.
- Team policies and quotas, a Requester role and on-behalf-of requests.
- Accessibility tooling (axe sweep in CI, keyboard journeys) and a draft ACR/VPAT built from automated evidence only.
- A whole-UI UX review and a security and code-health scan with fixes. The report is [docs/security/V1_SCAN_2026-10-17.md](../security/V1_SCAN_2026-10-17.md).
- A fresh hub now starts with zero CAs so the onboarding wizard can create the root. Several items stayed open, including bulk reissue.
