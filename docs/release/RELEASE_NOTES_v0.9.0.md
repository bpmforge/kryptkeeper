# Kryptkeeper v0.9.0

Kryptkeeper is a self-hosted machine-identity and certificate-lifecycle
platform: a Go hub that runs your own CAs, issues certificates over ACME, EST,
SCEP, CMP and Microsoft autoenrollment (WSTEP/XCEP), publishes CRL and OCSP,
issues SSH certificates, discovers and inventories certificates across a
fleet, and renews and installs them without manual steps. A React dashboard
sits on top of the API. It runs from Docker Compose, Helm, Terraform or a
plain binary on SQLite or Postgres.

This is the **first public release**. Earlier versions (v1.0 to v2.2) were
internal milestones and were never published. Treat v0.9.0 as a release
candidate for 1.0: the core is validated against real clients (below), several
areas are labelled beta or experimental, and the version number says so.

## Highlights

- **Issuance and CAs:** root and intermediate CAs, templates with name,
  key-strength and SSH policy, CSR-in issuance, renew, revoke, import, fullchain
  download, PQC (ML-DSA, hybrid) certificates with software keys.
- **Protocols:** ACME (http-01, dns-01 for wildcards), EST, SCEP with one-time
  challenges, CMP, WSTEP/XCEP for Windows GPO autoenrollment, CRL and OCSP.
- **Unattended renewal:** the scheduler renews and installs on nginx, Apache or
  HAProxy over SSH, on hosts running the agent, and on F5, Citrix, Kubernetes
  and IIS targets. It verifies the served certificate, rolls back on failure,
  retries with backoff, and tells the owner when it gives up.
- **Delivery plugins:** sandboxed WebAssembly plugins with signed manifests and
  trust tiers; F5 and Citrix ship as first-party plugins.
- **Discovery and inventory:** network TLS scan (including ML-KEM detection),
  Kubernetes and service-mesh discovery, WinRM agentless discovery (SSH agentless certificate discovery is not wired in v0.9),
  read-only Cloud Keys inventory page.
- **Governance:** append-only audit log with optional SIEM forwarding, approval
  queue with proposer and approver separated, key dual control on by default,
  custom roles, SSO (OIDC, SAML), SCIM, MCP server whose writes are
  proposal-only.
- **Postgres, fully tested:** every database-backed store has a round-trip test
  on PostgreSQL (users and API keys, notifications, CA lifecycle and more), and
  any purely additive migration is tolerated automatically on upgrade.
- **Key ceremonies:** root-CA ceremonies work on SQLite and PostgreSQL; a root
  stays pending until approved. A hub whose active CA has no key now refuses to
  start (`KRYPTKEEPER_ALLOW_MISSING_CA_KEYS=true` for recovery).
- **Notification rules:** rules persist and fire under the default `delivery`
  provider, and are validated.
- **Complete audit trail:** approval holds, dual-control proposals, skipped
  alerts and workload attestations are all stored (migration `000076`), and
  the Audit page and `GET /api/v1/audit?outcome=` filter by every outcome.
  Notification providers that only record (`file`, `db`) skip alerts and audit
  them as `skipped` instead of reporting them sent.
- **Template validity:** `validity_period` (`P30D`, `P1Y`, `72h`, `90d`) is
  honoured on issue and renew.
- **Security:** a deep audit run on 2026-10-09 and the fixes for it (below).

## What's validated

Results from 2026-10-11 on v0.9.0-rc.7 (`main` at `2f9e766`) against real clients (full table
in [`docs/release/LIVE_RESULTS_v0.9.md`](https://github.com/bpmforge/kryptkeeper/blob/v0.9.0/docs/release/LIVE_RESULTS_v0.9.md)).
Per-feature status for all 77 inventoried features is in
[`docs/release/FEATURE_VALIDATION_v0.9.md`](https://github.com/bpmforge/kryptkeeper/blob/v0.9.0/docs/release/FEATURE_VALIDATION_v0.9.md).

| Suite | Result | Real peer |
|---|---|---|
| Smoke (`tests/smoke`) | 331/331 | hub binary, curl, local OIDC JWKS stub |
| ACME (`tests/live/acme`) | 28/28 | certbot, lego |
| Protocols (`tests/live/protocols`) | all steps passed | openssl EST, SCEP, CMP, OCSP, CRL |
| TLS (`tests/live/tls`) | all steps passed | globalsign/est over the hub's own TLS |
| SSH CA (`tests/live/sshca`) | all steps passed | OpenSSH sshd and client |
| Plugins (`tests/live/plugins`) | all steps passed (27 checks) | example plugin, mock appliance, cosign |
| Autopilot (`tests/live/autopilot`) | all pass (29 checks) | nginx hosts and the agent, unattended |
| Agent (`tests/live/agent`) | 18 passed, 0 failed | Linux container agent |
| SSH install (`tests/live/ssh-install`) | all pass (nginx, apache, rollback) | OpenSSH, nginx, apache |

`go test ./...`, the same with a PostgreSQL 16 test database (`-p 1`), and `make test-race` each pass
on 50 packages. The upgrade test was re-run on rc.5 (nine scenarios on SQLite and PostgreSQL) and
spot-checked on rc.7 (SQLite rc.1 and rc.2 and PostgreSQL rc.4 to rc.7, schema 76, including audit rows with
the new outcomes being stored); see
[`UPGRADE_TEST_v0.9.md`](https://github.com/bpmforge/kryptkeeper/blob/v0.9.0/docs/release/UPGRADE_TEST_v0.9.md).

Older dated runs not repeated on 2026-10-11 (Kubernetes, service mesh, notifications,
PKCS#11 on SoftHSM2, Docker Compose, WinRM/IIS, WSTEP/XCEP on a Windows lab
with Kerberos) are recorded in [`docs/UAT_PLAN.md`](https://github.com/bpmforge/kryptkeeper/blob/v0.9.0/docs/UAT_PLAN.md).

## Beta, experimental, and not in v0.9

- **Beta** (works; unit and integration tested only): reports, compliance
  evidence, CBOM and PQC readiness; rollout groups and PQC migration waves;
  SAML, OIDC and SCIM (tested against in-process IdPs, not Keycloak, Okta or
  Entra); CT monitoring; cloud inventory; ADCS sync; Terraform provider;
  air-gap bundle; MCP server; Helm chart (never install-tested on a cluster);
  the UI has no browser end-to-end tests.
- **Experimental:** multi-tenancy (see Security); HashiCorp Vault and GCP Cloud
  KMS key stores (no tests).
- **Not verified on real hardware or accounts:** the F5 and Citrix plugins
  (mock devices only), cloud KMS (emulators only), SCEP from network devices,
  the ACME upstream connector against Let's Encrypt staging (dns-01 via
  Cloudflare; the live run is still pending).
- **Not in v0.9:** finding exceptions and risk acceptance (v0.10); issuer
  connectors other than `internal` and ACME (DigiCert, EST, SCEP and WSTEP
  upstream connectors).

## Upgrading from internal builds

v0.9.0 turns on several secure defaults. Before starting a v0.9.0 hub, read
**"Upgrade notes (breaking or behaviour changes)"** in the
[CHANGELOG](https://github.com/bpmforge/kryptkeeper/blob/v0.9.0/CHANGELOG.md#090---unreleased). The ones that stop a hub or
lock out an operator most often:

- Key export, backup and escrow need a second human to approve
  (`KRYPTKEEPER_KEY_DUAL_CONTROL=false` opts out).
- `AUTH_MODE=jwt` and `oidc` bearer tokens are read-only until
  `APP_AUTH_ROLE_CLAIM` and `APP_AUTH_ROLE_MAP_JSON` map a role.
- Secrets under 32 bytes, and OIDC mode without issuer and audience, are
  startup errors.
- Docker Compose needs `KRYPTKEEPER_KEYSTORE_PASSPHRASE`, different from the
  bootstrap token.
- SSH certificates need a template with an `ssh_policy`.
- Behind a reverse proxy, set `APP_TRUSTED_PROXY_CIDRS`.
- API keys minted through `POST /api/v1/api-keys` on earlier builds were lost at
  every restart; re-mint them once (CHANGELOG upgrade notes 56 and 57).
- An active CA with no key in the keystore stops the hub (note 58); existing
  notification rules start alerting (note 59); templates with `P1Y` now issue
  1-year certificates (note 60).

## Security

A deep audit of the whole repository (SAST, secrets in code and history,
dependencies, OWASP Web Top 10, OWASP LLM Top 10 for the MCP server, cloud,
IaC and CI, STRIDE threat model, 19 attack chains) ran on 2026-10-09 and
found 3 CRITICAL and 9 HIGH issues. A challenger review re-checked all 13
(none was wrong; three had their severity lowered). No live
secrets were found in code or git history, and no dependency is on the CISA KEV
list.

Everything CRITICAL and HIGH is fixed except tenant isolation. Fix groups FG-1
to FG-5 and FG-7 to FG-14 are merged (ACME issuance, key egress and separation
of duties, RBAC escalation, SSH CA policy, token hardening, login and session,
egress policy, issuance policy, plugins and MCP, cloud KMS, IaC and CI,
dependencies, documentation). Fixes ship with regression tests, and the live
smoke, ACME and SSH CA suites were re-run (results above).

**Known limits you should plan around:**

- **Multi-tenancy is experimental** (FG-6, due in v0.10). Tenant isolation is
  not a security boundary: a tenant admin can act across tenants. The hub
  refuses `MULTI_TENANCY` unless `KRYPTKEEPER_MULTI_TENANCY_EXPERIMENTAL=accept-risk`
  is set. Do not use it to separate mutually untrusting parties. See
  [`docs/design/TENANCY_POSTURE.md`](https://github.com/bpmforge/kryptkeeper/blob/v0.9.0/docs/design/TENANCY_POSTURE.md).
- Residual risks per OWASP category, such as in-memory refresh tokens and
  replay caches (a restart forgets them), a denylist rather than a sandbox for
  plugin `remote_exec`, and CMP using one shared secret per server, are listed
  in [`docs/security/OWASP_TRACKER.md`](https://github.com/bpmforge/kryptkeeper/blob/v0.9.0/docs/security/OWASP_TRACKER.md) and
  [`docs/security/final-report.md`](https://github.com/bpmforge/kryptkeeper/blob/v0.9.0/docs/security/final-report.md).

**Reporting a vulnerability:** do not open a public issue. Use GitHub's
private "Report a vulnerability" advisory on this repository, or email
security@kryptkeeper.io. Targets: acknowledgement in 48 hours, initial
assessment in 5 business days, coordinated disclosure within 90 days. Full
policy: [`SECURITY.md`](https://github.com/bpmforge/kryptkeeper/blob/v0.9.0/SECURITY.md).

## Install

```bash
git clone https://github.com/bpmforge/kryptkeeper.git
cd kryptkeeper
cp env.example .env     # set APP_BOOTSTRAP_TOKEN and KRYPTKEEPER_KEYSTORE_PASSPHRASE
docker compose up -d
```

Both values must differ; generate each with `openssl rand -hex 32`. The README
Quick Start continues through creating a template, issuing from a CSR,
fetching the CA certificate and verifying the chain. Helm, Terraform, binary
and air-gap installs are in [`docs/deployment.md`](https://github.com/bpmforge/kryptkeeper/blob/v0.9.0/docs/deployment.md) and
[`docs/ops/AIRGAP_INSTALL.md`](https://github.com/bpmforge/kryptkeeper/blob/v0.9.0/docs/ops/AIRGAP_INSTALL.md).

## Verify the release

The release workflow (`.github/workflows/release.yml`, driven by
`.goreleaser.yaml`) runs on a `v*` tag and publishes:

- archives for `kryptkeeper`, `kryptkeeper-agent`, `kryptkeeper-certmanager`
  and `kryptkeeper-mcp` (linux amd64 and arm64, darwin arm64), `.deb` and
  `.rpm` packages for the hub, `checksums.txt`, and a CycloneDX SBOM per
  archive;
- multi-arch images at `ghcr.io/bpmforge/<name>`, tagged `0.9.0`, `0.9` and
  `latest` (no `v` prefix).

**What is signed:** `checksums.txt` and the image manifests are signed
**keyless** with cosign (Sigstore, using the workflow's GitHub OIDC identity).
There is no long-lived signing key to fetch or trust. Archives, packages and
SBOMs are covered by the checksums, not signed individually.

```bash
V=0.9.0
curl -fsSLO https://github.com/bpmforge/kryptkeeper/releases/download/v$V/checksums.txt
curl -fsSLO https://github.com/bpmforge/kryptkeeper/releases/download/v$V/checksums.txt.sig
curl -fsSLO https://github.com/bpmforge/kryptkeeper/releases/download/v$V/checksums.txt.pem

cosign verify-blob \
  --certificate-identity "https://github.com/bpmforge/kryptkeeper/.github/workflows/release.yml@refs/tags/v$V" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --signature checksums.txt.sig --certificate checksums.txt.pem checksums.txt

sha256sum --ignore-missing -c checksums.txt   # after downloading an archive

cosign verify \
  --certificate-identity "https://github.com/bpmforge/kryptkeeper/.github/workflows/release.yml@refs/tags/v$V" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/bpmforge/kryptkeeper:$V
```

The image build and push has not been exercised end to end before this release
tag, so treat the first image verification as a check of the pipeline itself.
Delivery plugins are signed separately by their publishers with
`cosign sign-blob` (see `docs/ops/DELIVERY_PLUGINS.md`).

Full list of changes: [CHANGELOG](https://github.com/bpmforge/kryptkeeper/blob/v0.9.0/CHANGELOG.md).
