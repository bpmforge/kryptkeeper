# Kryptkeeper v0.9.0 — Feature Validation Inventory

Owner gate: "public after we have good basic features that work and validate."
Snapshot: 2026-10-09, `origin/main` 3a0b4fb. Updated 2026-10-11: section 2 (live results), section 4 (counts), the
plugins, agent, ssh-install, scheduler, API-key, Helm and upgrade rows, and the status banners on sections 5 and 6.
Built by reading README.md, docs/ROADMAP.md, docs/UAT_PLAN.md,
ui/src/App.tsx routes, docs/openapi.yaml, and grepping `internal/**/_test.go`, `tests/**`. No code was changed.
Evidence is cited as paths; "tests" counts are `func Test*` counts at this commit.

## 1. Status legend

| Status | Meaning |
|---|---|
| LIVE | A harness drives a real external client/system (certbot, openssl, OpenSSH, kind, Mailpit, SoftHSM2, Windows lab). |
| INTEGRATION | In-process or emulator test with real protocol encoding / real handler stack, no real third-party peer. |
| UNIT-ONLY | Package or handler unit tests only. |
| UNVALIDATED | Shipped code, no test that exercises it (or harness written but never run green). |
| HIDDEN / NOT-WIRED | Gated off, refused by the API, or reachable only as dead code. |
| EXT | Needs hardware, vendor appliance, cloud account, or production CA that is not available. A feature can be INTEGRATION plus EXT (emulated here, real thing unproven). |

## 2. Known live results (2026-10-11, v0.9.0-rc.7, `main` 2f9e766)

Source of truth: [LIVE_RESULTS_v0.9.md](LIVE_RESULTS_v0.9.md) (harness path, result, real client per row, run by the
coordinator). The 2026-10-09 table that stood here is superseded.

| Harness | Result | Real peer |
|---|---|---|
| `tests/smoke/run.sh` | 331/331 | the hub binary, curl, local OIDC JWKS stub |
| `tests/live/acme/run.sh` | 28 passed, 0 failed | certbot, lego (podman) |
| `tests/live/protocols/run.sh` | ALL STEPS PASSED | openssl EST/SCEP/CMP/OCSP/CRL |
| `tests/live/tls/run.sh` | ALL STEPS PASSED | globalsign/est over the hub's self-issued TLS |
| `tests/live/sshca/run.sh` | ALL STEPS PASSED | OpenSSH sshd + ssh client |
| `tests/live/autopilot/run.sh` | ALL PASS (29 checks) | nginx hosts and the agent, unattended |
| `tests/live/agent/run.sh` | 18 passed, 0 failed | Linux container agent |
| `tests/live/ssh-install/run.sh` | ALL PASS (nginx + apache, incl. rollback) | OpenSSH, nginx, apache |
| `tests/live/plugins/run.sh` | ALL STEPS PASSED (27 checks) | built-from-source example plugin, mock appliance, cosign; harness now on a podman network (PR #102) |
| Upgrade test | PASS | rc.7 (2f9e766) spot-check, schema 76: SQLite rc.1 and PostgreSQL 16 rc.4 to rc.7, including audit rows with the outcomes added by 000076 stored and filterable. Full matrix on rc.5 (5ec48ff), 2026-10-11: SQLite rc.1, rc.2, rc.3 and rc.1 file-audit to rc.5; PostgreSQL 16 rc.1, rc.3 and rc.4 to rc.5; non-`ca` provider first then `ca` on both engines; schema 75 on rc.5, data preserved, CRL/OCSP, issuance with old CAs, API-key restart/revoke, root-CA ceremony, template validity, notification rule persistence, missing-CA-key refusal: [UPGRADE_TEST_v0.9.md](UPGRADE_TEST_v0.9.md) |
| `tests/live/acme-upstream/run.sh` | exists, NOT RUN | needs Cloudflare token + LE staging |
| F5 / Citrix plugins | unverified | no device; only mock iControl/NITRO |

Older passes recorded in docs/UAT_PLAN.md (dated, not re-run on 2026-10-11): k8s 31/31, mesh 18/18, notifications 18/18,
pkcs11 23/23, compose 5/5 (all 2026-09-11 regression run); WinRM/IIS 2026-09-10; WSTEP/XCEP user + machine context
2026-10-08 (Windows lab, Kerberos); TLS/ML-KEM scan 2026-08-20; DR restore drill.

## 3. Feature matrix

### 3.1 Issuance and CAs
| Feature (claim) | Status | Evidence |
|---|---|---|
| Root/intermediate CA create, activate, suspend, chain | INTEGRATION | smoke `/cas*` (9+3+3 asserts, file-provider fixtures); `internal/ca` 116 tests; the CA engine is exercised by every LIVE harness |
| Certificate issue (CSR-in), renew, revoke, import, download | INTEGRATION | smoke `/certificates*` incl. renew/revoke/import/chain/download; `handlers_certificates_test`; real issuance in all live protocol harnesses |
| Templates CRUD/clone, name/SAN/key-strength policy | INTEGRATION | smoke `/templates*` (tpl-tls-90d, clone, in-use delete); `template_policy_test`, `name_policy_test`, `policy_engine_test` |
| Bulk revoke/reissue, ownership, bulk import | UNIT-ONLY | `handlers_bulk_test`, `handlers_bulk_import_test`; no smoke/live |
| CA rotation / re-key / cross-sign | UNIT-ONLY | `ca/rotation_test`, `ca/cross_sign_test`, `ca_rotation_test` |
| PQC certs (ML-DSA, hybrid, mixed) | UNIT-ONLY | `ca/mldsa_cert_test`, `hybrid_*_test`, `mixed_cert_test`; software keys only (docs/ADR_PQC_KEYS_SOFTWARE_ONLY.md); no OpenSSL-3.5/ OQS interop |
| Code-signing policy/issuance | UNIT-ONLY | `handlers_codesign_test`, `codesign_policy_test`; UI page `/code-signing`; no signtool/jarsigner check |
| Key ceremony (M-of-N), escrow, BYOK, backup/export | UNIT-ONLY | `ca/ceremony_test`, `handlers_ceremony_test`, `keystore/escrow_test`, `byok*_test`, `export_import_test`; DR restore drill is LIVE (docs/ops/DR_RUNBOOK.md) |

### 3.2 Protocols
| Feature | Status | Evidence |
|---|---|---|
| ACME (RFC 8555) http-01 | LIVE | `tests/live/acme/run.sh` certbot + lego: issue/renew/revoke, chain, inventory source=acme, CRL/OCSP. Server-side dns-01/tls-alpn not shown live |
| ACME EAB | UNIT-ONLY | `acme` TestVerifyExternalAccountBinding_* (134 acme tests total) |
| EST (RFC 7030) over TLS | LIVE | `tests/live/tls/run.sh`, `protocols/est-run.sh` (globalsign/est); `internal/est` 17 tests |
| SCEP (RSA CA) | LIVE | `protocols/scep-run.sh` (micromdm/scep client); `internal/scep` 17 tests. No real network-device SCEP client (F5/Citrix/PAN) |
| CMP (RFC 4210, PBM) | LIVE | `protocols/cmp-run.sh` (openssl cmp); `internal/cmp` 18 tests |
| OCSP / CRL | LIVE | `openssl ocsp` + CRL fetch after real revocation in acme + protocols harnesses; cache invalidation tests in `internal/ocsp` |
| MS-WSTEP / MS-XCEP | LIVE (lab) | `tests/live/wstep` real Kerberos/AD; GPO autoenrollment on Windows 11 2026-10-08. Needs Windows lab: not reproducible in CI |
| SPIFFE (SVID, bundle, Workload API gRPC) | INTEGRATION | `spiffe_workload_grpc_test`, `spiffe_hardening_test`, `handlers_spiffe_test`; no SPIRE/go-spiffe client harness |
| Protocol status/readiness/conformance API | INTEGRATION | smoke `/protocols/status|readiness|conformance` (+recheck) |

### 3.3 SSH CA
| SSH user/host certs, principals, TTL ceiling, template ssh_policy | LIVE | `tests/live/sshca/run.sh` real sshd refuses wrong principal/expired/bare key; `sshkeys` 12 tests, `template_ssh_policy_test` |
|---|---|---|
| SSH key inventory | UNIT-ONLY | `sshkeys/inventory_test` |

### 3.4 Discovery and inventory
| Feature | Status | Evidence |
|---|---|---|
| Network TLS scan (full/targeted/deep, ML-KEM detection) | LIVE | UAT_PLAN 2026-08-20 (Go TLS 1.3 server + IIS); `discovery/scanner` tests; smoke covers only the file provider (422 on writes) |
| Kubernetes cert-manager discovery | LIVE | `tests/live/k8s/run.sh` (kind) |
| Service-mesh discovery (Istio/Linkerd) | LIVE | `tests/live/mesh/run.sh` |
| WinRM agentless discovery | LIVE (lab) | `agentdiscovery/live_winrm_test.go`, `KK_LIVE_WINRM=1`, Windows 11 host |
| Agentless SSH install | LIVE | `tests/live/ssh-install/run.sh` ALL PASS 2026-10-11 |
| Agentless SSH certificate discovery | NOT-WIRED (planned) | `agentdiscovery.AgentlessSSHScanner` exists with unit tests but has no production caller; no API or scheduler path runs it |
| CT-log monitoring | UNIT-ONLY | `internal/ctmonitor` 11 tests (matching/inventory); no real CT log query |
| Cloud inventory (AWS/Azure/GCP certs+keys) | UNIT-ONLY, EXT | `cloudinventory` 18 tests, `cloud_discovery_test`; fakes |
| Estate sources: ADCS LDAP sync-in | UNVALIDATED | `tests/live/ad-ldap` harness written, blocked 2026-09-10 (Samba provisioning); `inventory_source_adcs_live_test` unit |
| Estate sources: DigiCert/Sectigo/Entrust/AWS-PCA/GCP-CAS read-only pull | UNIT-ONLY, EXT | `inventory_source_commercial_test` (httptest) |
| Estate model, takeover, dedup, bulk import | UNIT-ONLY | `estate_model_test`, `connector_estate_test`, `handlers_bulk_import_test` |
| Inventory search / dashboard summary / actions | INTEGRATION | smoke `/search`-adjacent, `/dashboard/*` (summary, actions ack/resolve/history) |

### 3.5 Agents
| kryptkeeper-agent enroll, inventory push, renewal task | LIVE | `tests/live/agent/run.sh` 18 passed, 0 failed (2026-10-11), Linux container agent against the hub in TLS mode |
|---|---|---|
| Agent attestation / enrollment secrets, assignment | UNIT-ONLY | `agent_attestation_test`, `handlers_agents*_test`; partly covered by the live agent run |
| Windows agent / macOS keychain installer | UNVALIDATED | `tests/live/keychain` gated on `KK_LIVE_KEYCHAIN=1` and a disposable Mac; not in any known green run |

### 3.6 Renewal, rollout, delivery (connectors, plugins)
| Feature | Status | Evidence |
|---|---|---|
| Renew + install nginx/apache over SSH, verify, rollback | LIVE | `tests/live/ssh-install/run.sh` ALL PASS (nginx + apache incl. rollback) 2026-10-11 |
| IIS install via WinRM | LIVE (lab) | UAT_PLAN 2026-09-10 |
| Kubernetes Secret push | LIVE | `tests/live/k8s/run.sh` |
| Renewal scheduler/autopilot, retry, dead-letter, SLO sweep | UNIT-ONLY | `renewal_scheduler*_test`, `renewal_retry`, `handlers_renewal_slo_test`; live notifications run triggers the startup scan once. `tests/live/autopilot/run.sh` (29 checks, nginx hosts and the agent, unattended) ALL PASS 2026-10-11 covers the renew-and-install path; retry, dead-letter and SLO sweep have no live case, so the row keeps its status |
| Rollout groups / canary, PQC migration waves | UNIT-ONLY | `rollout_groups_test`, `pqc_waves_test`, `pqc_wave_execute_test` |
| Delivery-plugin framework (install, approval, sandbox, kill switch, cosign) | LIVE | `tests/live/plugins/run.sh` ALL STEPS PASSED, 27 checks, 2026-10-11, after the harness moved onto a podman network (PR #102; earlier 26 checks on 2026-10-09); `tests/plugins/conformance` |
| F5 BIG-IP / Citrix ADC plugins and built-in pushers | INTEGRATION, EXT | `tests/plugins/conformance/appliances_test.go` against mock iControl/NITRO; no real device |
| ACME upstream connector (renew at LE via dns-01) | UNVALIDATED, EXT | `connector_acme*_test` with fake CA; `tests/live/acme-upstream` never run |
| DigiCert / EST / SCEP / WSTEP issuer connectors | NOT-WIRED | `connector_store.go` `validConnectorTypes` = internal, acme only; `buildRuntimeConnector` returns nil otherwise; `internal/connectors/{digicert,est_client,scep_client,wstep_client}.go` unit-tested but unreachable |

### 3.7 Notifications and SIEM
| Email (SMTP), webhook, scheduled expiry alert | LIVE | `tests/live/notifications/run.sh` Mailpit + echo receiver; `notifications/delivery` tests |
|---|---|---|
| Slack, SIEM webhook | INTEGRATION | same harness asserts Slack/Splunk-shaped payload to a stand-in receiver; no real Slack/Splunk |
| PagerDuty, Teams, syslog (RFC 5424) | UNIT-ONLY | README states PagerDuty not exercised (pinned to real endpoint); `siem_integration_test` |
| Alert rules, silences, dedup, retry/ack | INTEGRATION | smoke `/notifications/*` (deliveries retry/ack, summary, test-delivery); `notification_*_test`, `handlers_notification_*_test` |

### 3.8 Reports, compliance, PQC
| Reports (CA health, expiry, revocation, velocity, change-audit, algorithm-sunset) | UNIT-ONLY | `handlers_reports_test`, `report_export_test`, `report_tenant_scope_test`; 32 `Reports` operations in openapi, none in smoke |
|---|---|---|
| Compliance evidence packs (SOC2/PCI/DORA/NIS2), PDF, scheduled | UNIT-ONLY | `evidence_pdf_test`, `evidence_scheduler_test`, `compliance_dora_nis2_test` |
| CBOM export, crypto-posture, PQC readiness/countdown/agility | UNIT-ONLY | `cbom_export_test`, `pqc_readiness_test`, `handlers_pqc_*_test`, `pqc/*_test` |
| Audit log (append-only), audit trust/anchoring | INTEGRATION | smoke `/audit` (11 asserts); `audit_store_test`, `audittrust` |
| Finding exceptions / risk acceptance / suppression | HIDDEN | no API creates exceptions; UI hides until v0.10 (ROADMAP W2/W3; Discovery.tsx, CryptoPosture.tsx) |

### 3.9 Auth
| Bootstrap token, HS256 JWT, role claim mapping | INTEGRATION | smoke authz-check/protected/* across bootstrap and jwt modes (~70 asserts) |
|---|---|---|
| OIDC bearer (JWKS rotation) | INTEGRATION | smoke with python JWKS provider; `auth_oidc*_test`; no real IdP |
| OIDC login (auth-code flow), SAML SSO | INTEGRATION | `auth_oidc_login_test`, `auth_saml_test`, `auth_saml_guard_test` in-process IdP; no Keycloak/Okta/Entra/ADFS |
| SCIM 2.0 users/groups | UNIT-ONLY | `scim_test`; no Okta/Entra provisioning client |
| API keys; local login/session/refresh | INTEGRATION | smoke `/api-keys`, `/auth/login`, `/auth/refresh`; `handlers_apikeys_test`. Keys minted via `POST /api/v1/api-keys` were memory-only through rc.2 and main 26e17ca (lost on restart; UPGRADE_TEST_v0.9.md finding 2). Persistence in the core database is merged (PR #105, migration 000074): unit tests `TestMintedAPIKeySurvivesRestart`, `TestRevokedAPIKeyStaysRevokedAfterRestart`, `TestMintFailsClosedWhenPersistenceFails`, `TestRevokeFailsClosedWhenPersistenceFails`, `TestMintedAPIKeySecretIsNeverStored`. Live restart check on rc.5 (5ec48ff, `UPGRADE_TEST_v0.9.md` re-run, 2026-10-11), sqlite and PostgreSQL 16: a minted key authenticates after a container restart (200), DELETE returns 204, the key returns 401 immediately and after a further restart, the static `APP_API_KEYS_JSON` key is unaffected, and the secret is not in the database; on PostgreSQL `POST /api/v1/api-keys` returns 201 and `GET /api/v1/users` 200 with the default user provider (rc.3 and rc.4 returned 503, fixed in rc.5) |
| Custom RBAC roles, SoD | UNIT-ONLY | `authz_custom_roles*_test`, `separation_of_duties_helpers_test` |
| Rate limiting, security headers, trusted-proxy client IP | UNIT-ONLY | `ratelimit` 13, `clientip`, `http_security_test` |

### 3.10 Approvals and dual control
| Approval queue (self-approval refused), pending actions | INTEGRATION | `approval_store_test`, `handlers_approvals_test`, `pending_actions_test`; live plugins harness shows 202 pending, self-approve 403, second admin approves |
|---|---|---|
| Key dual control (destroy/export grants) | UNIT-ONLY | `key_dual_control_test`, `key_egress_dual_control_test` |

### 3.11 Keystore backends
| Software (PKCS#8, Argon2id) | LIVE (implicit) | backend of every live harness; `keystore/software_test` |
|---|---|---|
| PKCS#11 | LIVE (SoftHSM2), EXT | `tests/live/pkcs11/run.sh` 23/23; no vendor HSM (Thales/Entrust/AWS CloudHSM) |
| AWS KMS | INTEGRATION, EXT | `tests/live/kms-aws` vs moto; README: DIGEST semantics and IAM unproven |
| Azure Key Vault | INTEGRATION, EXT | `tests/live/kms-azure` vs Lowkey Vault with stub Entra |
| GCP Cloud KMS | UNVALIDATED | `keystore/cloudkms_gcp.go` has no test and no emulator harness; README lists it as supported |
| HashiCorp Vault transit | UNVALIDATED | `keystore/vault.go` has no test file and no harness |
| FIPS posture, key-gen policy, secure destroy | UNIT-ONLY | `fips_test`, `keygen_policy_test`, `destroy_test` |

### 3.12 MCP server
| Read tools, proposal-only write tools, HTTP transport | INTEGRATION | `internal/mcpserver` 28 tests (`TestProposeRevoke_EnqueuesOnly`), `mcp_role.go`; no real MCP client (Claude Desktop) run |
|---|---|---|

### 3.13 Multi-tenancy (experimental)
| Tenants, X-Tenant, ca/template mapping | EXPERIMENTAL / HIDDEN | `tenancy_experimental.go` refuses start without `...EXPERIMENTAL=accept-risk`; `tenant_*_test`; docs/design/TENANCY_POSTURE.md. UI `/tenants` shows an experimental banner |
|---|---|---|

### 3.14 Deployment
| Docker Compose + TLS (healthcheck, nginx trust) | LIVE | `tests/live/compose/run.sh` 5/5 (podman compose) |
|---|---|---|
| Helm chart `charts/kryptkeeper` | UNVALIDATED | `helm lint` and `helm template` pass (ANTI_SLOP_RC2.md, 2026-10-10, run by hand); no install on a cluster and no helm step in any workflow or test; chart version 0.9.0 |
| cert-manager issuer chart + `kryptkeeper-certmanager` | UNIT-ONLY | `certmanagerissuer` 6 tests; no cluster install |
| Terraform provider | UNIT-ONLY | `terraform-provider-kryptkeeper/internal/provider/provider_test.go`, CI `terraform-provider.yml`; no apply against a hub |
| `deploy/terraform` modules, air-gap bundle | UNVALIDATED | no tests found |
| Postgres migrations / upgrade | INTEGRATION | `tests/protocol/run.sh`, `db_core_migration_upgrade_test`, `TestRunMigrations_Postgres*` (needs DSN), DR drill; container upgrade test PASS on rc.5 2026-10-11: rc.1, rc.3 and rc.4 to rc.5 on PostgreSQL 16, and default-provider-then-`ca` on PostgreSQL ([UPGRADE_TEST_v0.9.md](UPGRADE_TEST_v0.9.md)) |
| UI (35 pages) | UNIT-ONLY | 44 vitest files in `ui/src`; no browser E2E (Playwright not a declared dependency; ci-pr.yml probes for it and skips) |

## 4. Counts

Primary status per feature row (rows with "plus EXT" counted under their emulated status; EXT overlay counted separately).

| Status | Rows |
|---|---|
| LIVE (incl. lab, implicit, SoftHSM2) | 21 |
| INTEGRATION | 19 |
| UNIT-ONLY | 26 |
| UNVALIDATED | 7 |
| HIDDEN / NOT-WIRED / EXPERIMENTAL | 4 |
| Overlay: EXT (real hardware/cloud/vendor unproven, already counted above) | 7 |

Total rows: 77 (26 + 21 + 19 + 7 + 4; recounted by script over the section 3 tables on 2026-10-11). Roughly a quarter have a real-client harness; the core PKI path (issue, ACME/EST/SCEP/CMP, OCSP/CRL,
SSH CA, agent, SSH/k8s install, notifications, PKCS#11-on-SoftHSM) is the validated set.

## 5. Gaps for public v0.9 (ranked by user impact)

Status: this list is as of 3a0b4fb (2026-10-09) and was not rewritten. Updates since: gap 1, `helm lint` and `helm template`
now pass (ANTI_SLOP_RC2.md), the README values are fixed, install on a cluster is still open; gap 4, the live autopilot harness
passed 2026-10-11 (section 2), so the renew-and-install path now has a live case. Gaps 2, 3 and 5 to 13 were not re-checked.

| # | Gap | Impact | Recommendation |
|---|---|---|---|
| 1 | Helm chart never linted/templated/installed; README Helm command uses non-existent values | High: primary production install path | Add `helm lint` + `helm template` + kind install smoke (reuse tests/live/k8s kind setup); fix README values now |
| 2 | Compliance/evidence/reports/CBOM only unit-tested (32 report operations, no smoke) | High: headline value for auditors | Add smoke assertions for `/reports/*` and an evidence-pack download with schema check; ship as stable only if green |
| 3 | UI has no browser E2E | High: UI is the first impression | Add a minimal Playwright login-issue-revoke journey or label UI "beta" in README |
| 4 | Auto-renewal scheduler/rollout/PQC waves unit-only | High: "autopilot" is a core claim | Add live case: scheduler renews and agent/ssh installs without a manual call (extend ssh-install) ; else label beta |
| 5 | HashiCorp Vault and GCP KMS backends have no tests | High: advertised in README and `KEY_BACKEND` | Add Vault dev-server harness (free, like moto) and a GCP fake-endpoint test, or mark "experimental" in README/env.example |
| 6 | SAML, SCIM, OIDC login only against in-process IdP | Medium-high: enterprise gate | Add Keycloak container harness (OIDC+SAML+SCIM-adjacent); label "beta" until then |
| 7 | F5/Citrix plugins and SCEP-for-network-devices unproven on real gear | Medium (README markets F5/Citrix/PAN) | State "conformance-tested against mocks, unverified on appliances" in README + UI plugin page |
| 8 | ACME upstream connector never run against LE staging | Medium | Run `tests/live/acme-upstream` once the Cloudflare token is available; label beta until done |
| 9 | Connector types DigiCert/EST/SCEP/WSTEP not wired; `internal/connectors` clients dead code | Medium: confusing roadmap vs product | Keep API refusal; state in README/docs "connectors: internal and ACME only"; do not show as options in UI |
| 10 | Finding exceptions hidden; funnel "suppressed" always 0 | Low-medium | Keep hidden; confirm no UI element mentions exceptions outside the v0.10 comments |
| 11 | CT-log monitoring, cloud inventory, ADCS LDAP, commercial-CA pulls unit-only | Medium | Label beta; run ad-ldap on a host that can provision Samba (or reuse the Windows lab DC) |
| 12 | Multi-tenancy | Low | Already experimental-gated and documented; keep out of feature lists |
| 13 | Terraform provider/air-gap/deploy modules, macOS keychain, MCP with a real client | Low | Label beta or add a single smoke apply/run |

## 6. README claims that do not match the code

Verified by grep at 3a0b4fb (2026-10-09). Status at RC2 (ANTI_SLOP_RC2.md, 2026-10-10, README re-grepped): items 1 to 5 are
RESOLVED (zero hits for `APP_JWT_SECRET`, `APP_AUTH_MODE`, the old Helm flags and "Go 1.25+"; the README Helm example uses
`secrets.*` and `ingress.hosts[0]`). Items 6 to 12 were not re-checked and should be read as open.

1. Config/Binary section uses `APP_JWT_SECRET`; code reads `APP_JWT_HS256_SECRET` (zero hits for `APP_JWT_SECRET` in `cmd/` and `internal/`). Quick Start and the binary example would start with no JWT secret.
2. README API section says `APP_AUTH_MODE=jwt` / `APP_AUTH_MODE=oidc`; the code reads `AUTH_MODE` (`auth_config.go:126`), also the name in the config table. Zero hits for `APP_AUTH_MODE`.
3. "Bootstrap token (from container logs on first start)" contradicts Quick Start step 1 ("nothing generates or logs one for you") and `auth_config.go`, which never prints a token.
4. Helm example flags `postgresql.auth.password`, `config.jwtSecret`, `ingress.host` do not exist: `values.yaml` has no postgresql sub-chart, uses `secrets.bootstrapToken`, `secrets.keystorePassphrase`, `secrets.databaseURL`, and `ingress.hosts[]`.
5. "Go 1.25+" appears twice; `go.mod` says `go 1.26.0` (CLAUDE.md also says 1.26).
6. Key Storage table lists AWS KMS / GCP / Azure and Vault as production tiers; GCP and Vault have no tests, and AWS/Azure are emulator-only. "Verified against real systems" says 13 passed / 4 blocked, but F5/Citrix and cloud KMS are still listed under it without per-feature qualification.
7. SCEP row says "Network devices (F5, Citrix, Palo Alto)"; only micromdm/scep and openssl were run. No device has been tried.
8. "Verified against real systems" counts (13/0/0/4) come from UAT_PLAN dated 2026-09-11; WSTEP is now passed, so the live count is stale, and the protocols README table in `tests/live/protocols/README.md` still shows 2026-09-10 FAILs that were later fixed.
9. "Commercial features (FIPS validation, multi-tenancy, HSM key ceremony tooling) planned for a future tier": a key-ceremony API and FIPS-posture code already ship in OSS (`handlers_ceremony.go`, `keystore/fips.go`).
10. Intro and API list omit that finding exceptions, DigiCert/EST/SCEP/WSTEP connectors, and multi-tenancy are not usable; only multi-tenancy has a README note.
11. `tests/README.md` is stale (calls the repo "docs-first", says protocol suite "Later"), contradicting the 331-assert smoke suite and real protocol harnesses.
12. Security section: "Rate limiting on ACME, OCSP, CRL, EST, and SCEP" is true (`main.go:518-523`) and also covers CMP, so only a minor omission. "All endpoints require authentication" is false for protocol endpoints (ACME/EST/OCSP/CRL are protocol-authenticated); clarify.
