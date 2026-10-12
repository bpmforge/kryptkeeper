# THREAT_MODEL_FINDINGS 2026-10-09 (kryptkeeper, --deep audit, threat-model phase)

## Coverage statement (read first)

- Method: STRIDE per component over the DFD in `docs/sdlc/phase-3-design/THREAT_MODEL.md` §8 (2026-10-09 addendum). Every threat is mapped to a confirmed finding from the sibling files of this date, or to a control read in code, or flagged **GAP** (no control and no finding) or **UNASSESSED** (nobody looked).
- Inputs read: SEMGREP, SECRETS, DEPENDENCY, OWASP_WEB, OWASP_A01 (+ supplement), OWASP_A02_A07 (+ supplement), OWASP_A03_A08_A10, LLM, CLOUD findings of 2026-10-09. `IaC_FINDINGS_2026-10-09.md` did not exist when read, so IaC is UNASSESSED here.
- The ACME CRITICAL passed in the HANDOFF is now in a file as **OWASP-A04-001**. It is mapped to that ID and not re-raised.
- New code reads in this phase (no live test): `internal/bootstrap/authz_custom_roles_handlers.go:57-67`, `authz_custom_roles.go:296-318`, `authz_write_gate.go:116-121,163-213`, `handlers_users.go:63-112`, `user_db_provider.go:93-110`, `scim.go:173,233`, `auth.go:240-270`, `handlers_pending_actions.go:22-31,157-196`, `notification_db_provider.go:271-302`, `internal/agentinstall/executor_ssh.go:75-98`, `internal/plugins/delivery/runtime.go:51-52`, `cmd/kryptkeeper/main.go:512-516`.
- category: `threat-model` for all entries below.

## Summary

| Rating | Threats | of which GAP |
|---|---|---|
| CRITICAL | 2 | 0 |
| HIGH | 8 | 1 |
| MEDIUM | 22 | 1 |
| LOW | 12 | 1 |
| **Total** | **44** | **3** |

Full register (ID, STRIDE, component, rating, findings, controls) is in THREAT_MODEL.md §8.5. The GAP entries are written out in full below in finding schema; everything else is already a finding in a sibling file.

## GAP findings (no control, no prior finding)

### TM-08: A custom role holding `user.manage` can grant itself, or any user, `pki-admin` (self-referential permission gate)
- id: TM-08 | severity: HIGH | category: threat-model | tool: manual (code read) | status: REAL (code path), not live-tested
- file: internal/bootstrap/authz_custom_roles_handlers.go:57-67 (`roleMayManageRoles` passes any role for which `RoleHasPermission(role, "user.manage")` is true); authz_custom_roles.go `CreateRole`/`UpdateRole` (accepts any vocabulary permission, including `user.manage` itself, with no check that the grantor holds what it grants); authz_write_gate.go:116-117 (`/api/v1/users/**` and `/api/v1/roles/**` need only `user.manage`); handlers_users.go:63-74,102-112 (invite and PATCH pass `req.Role` straight to the provider, with no admin check); user_db_provider.go:105-107 (role string written unvalidated).
- evidence: The gate that protects role and user management is the permission that role management grants. A principal on a custom role with `user.manage` can (a) `PUT /api/v1/roles/<own role>` with the full permission vocabulary, or (b) `PATCH /api/v1/users/<own id>` with `{"role":"pki-admin"}` (or `"bootstrap"`, which `fixedRolePermissions` and `principalPermissions` also treat as admin). New sessions then carry `pki-admin`. Only `pki-admin` holds `user.manage` among the fixed roles, so the precondition is that an admin delegated user management through a custom role, which is the purpose of custom roles.
- preconditions: ["custom role containing user.manage assigned to the attacker", "custom-role store enabled (DB mode)"]
- yields: ["pki-admin role (all permissions, admin flag)", "under MULTI_TENANCY: chains into A01-001 / A01S-3 cross-tenant takeover"]
- asset: RBAC integrity; every admin-gated asset (keys, CAs, config)
- remediation: Require the caller to hold every permission it grants (role create/update) and to hold `pki-admin` to assign `pki-admin`; validate role names on invite/PATCH against fixed + custom roles and refuse `bootstrap`; refuse self-modification of one's own role or user record; make role changes a dual-control pending action.

### TM-43: Notification destinations (webhook URLs, which often embed tokens) are stored and listed in plaintext
- id: TM-43 | severity: MEDIUM | category: threat-model | tool: manual (code read) | status: UNVERIFIED (whether targets carry secrets depends on the channel)
- file: internal/bootstrap/notification_db_provider.go:271-302,458-479 (`target` inserted as-is into `notification_deliveries`), :203,389 (scanned back for listing); no AES/GCM/seal call in `internal/notifications` or `notification_*` (only `outbound_credential_store.go` seals secrets).
- evidence: The 1.0 threat model (§1 Data Classification) says notification channel configs are encrypted at rest with AES-256-GCM and never returned in plaintext. The delivery log stores the target verbatim and the list path returns it. Slack/Teams/generic webhook URLs are bearer secrets.
- preconditions: ["certificate.read or notification.manage to list deliveries, or DB/backup read access"]
- yields: ["webhook bearer URLs (post as the platform into the operator's chat/incident tooling)"]
- asset: notification channel secrets
- remediation: Keep channel secrets in the sealed outbound credential store and reference them by id; redact the target (host only) in the delivery log and API.

### TM-44: No in-application enforcement of TLS to Postgres
- id: TM-44 | severity: LOW | category: threat-model | tool: manual (grep) | status: REAL (absence of control)
- file: `sslmode` appears only in deploy/terraform/modules/compute/templates/user_data.sh.tpl:108. The hub accepts whatever `DATABASE_URL` / `KRYPTKEEPER_DB_DSN` / `APP_NOTIFICATION_DB_DSN` it is given (notification_db_provider.go:40-64) and does not refuse `sslmode=disable` outside dev.
- preconditions: ["network position between hub and Postgres", "operator DSN without sslmode=require/verify-full (compose/Helm/manual installs)"]
- yields: ["read/modify certificate, approval, user and audit rows in transit"]
- asset: database tier integrity and confidentiality
- remediation: In non-dev mode, refuse a Postgres DSN whose sslmode is not `verify-full` (or `require` with an explicit override flag), and log the effective mode at startup.

## Threat-to-finding map (non-GAP threats)

| Threat | Rating | Findings |
|---|---|---|
| TM-01 ACME finalize issues any name | CRITICAL | OWASP-A04-001 |
| TM-02 ACME http-01 unauthenticated SSRF | HIGH | OWASP-A10-001 |
| TM-03 Tenant admin mints API keys in any tenant | CRITICAL (MT on) | A01-001, A01S-1 |
| TM-04 Tenant admin exports another tenant's CA key / global ssh-ca | HIGH (MT on) | A01S-3, A01-006 |
| TM-05 Approval executes against other tenants' targets | HIGH (MT on) | A01-002, A01S-2 |
| TM-06 Approval executes more than once (race) | MEDIUM | A01-003 |
| TM-07 Proposer != approver bypass (minted principal_id, shared MCP token) | MEDIUM | A07-4, LLM-006 |
| TM-09 OIDC empty iss/aud: any IdP token = service-account that issues | HIGH (chain) | A02-4, A2A7-009 |
| TM-10 SSH certificates: no principal/template policy, one global SSH CA | HIGH | A01S-4 |
| TM-11 Weak HS256 secret: forge `role: pki-admin` session | MEDIUM | A02-3, A2A7-009 |
| TM-12 Bootstrap token: permanent, non-constant-time, no floor | LOW | A07-6, A2A7-009 |
| TM-13 Local login verifier has no work factor | MEDIUM | A2A7-002 |
| TM-14 Logout revokes nothing; refresh keeps login-time role | MEDIUM | A2A7-003, A07-5 |
| TM-15 OIDC links accounts by unverified email | MEDIUM | A2A7-006, A07-3 |
| TM-16 OIDC login CSRF, no nonce | LOW | A2A7-007 |
| TM-17 SAML replay and RelayState `/\host` redirect | MEDIUM | A2A7-008, A2A7-005, A07-1, A07-2 |
| TM-18 Unknown `kid` forces JWKS refetch | MEDIUM | A2A7-004 |
| TM-19 SCIM bearer assigns any role, including pki-admin | MEDIUM | none; control: constant-time bearer, fails closed when unset (by-design IdP trust) |
| TM-20 Escrow/backup bypass key dual control; dual control off by default | HIGH | A2A7-001, A02-5 |
| TM-21 Cross-tenant reads (audit, search, CBOM, SSH certs, totals, MCP tools) | HIGH (MT on, via MCP) | A01-004, A01-005, A01-007, A01S-5, LLM-001, LLM-002 |
| TM-22 Tenant admin changes global config/credentials/plugins/users | MEDIUM (MT on) | A01-006, A01S-6 |
| TM-23 Audit attribution spoofable (XFF IP, X-Tenant, tenant=default) | LOW | OWASP-001, OWASP-002, A01-004 |
| TM-24 Write gate decoded-vs-escaped path mismatch | LOW | A01S-7, SEMGREP-009 |
| TM-25 OCSP signs for unknown issuers, serial-only cache, fails open | MEDIUM | SEMGREP-012, SEMGREP-013 |
| TM-26 ACME revoke recorded against default CA on DB error | LOW | SEMGREP-014 |
| TM-27 Protocol DoS: ACME nonce flush, CMP PBM iterations, CIDR expansion | LOW | OWASP-A04-003, -004, -005 |
| TM-28 No key-strength floor on ACME/CMP | MEDIUM | OWASP-A04-002 |
| TM-29 MCP HTTP transport: no auth, no Origin/Host check, no body cap | MEDIUM | LLM-004, A01S-8 |
| TM-30 MCP indirect prompt injection via raw Hub JSON | MEDIUM | LLM-003 |
| TM-31 MCP proposal body unbounded | MEDIUM | LLM-005 |
| TM-32 Agent token in process log; in-memory store `!=` compare | LOW | SEMGREP-004, A07-7 |
| TM-33 WinRM cmdQuote misses `&|^<>` (IIS fields) | LOW | OWASP-A03-001 (UNVERIFIED runtime) |
| TM-34 cert-manager connector disables TLS verification with a bearer token | MEDIUM | SEMGREP-003 |
| TM-35 Plugin `elevated_exec` checked on argv[0] basename only | MEDIUM | OWASP-A08-001 |
| TM-36 Outbound SSRF: webhooks, inventory sources, ACME connector probe, SIEM | MEDIUM | SEMGREP-001, SEMGREP-002, OWASP-A10-002, SEMGREP-007 (UNVERIFIED) |
| TM-37 Cloud KMS: unauthz inventory, account-wide IAM, software-protected GCP/Azure keys, unpinned Azure token host | MEDIUM | CLOUD-001..009 |
| TM-38 SPIFFE handler returns server-generated `key_pem` | MEDIUM | SEMGREP-010 (UNVERIFIED) |
| TM-39 Browser: no security headers; cookie Secure from X-Forwarded-Proto | LOW | OWASP-003, OWASP-004 |
| TM-40 Vulnerable dependencies (terraform-provider gRPC authz bypass; toolchain floor) | MEDIUM | DEP-001 (HIGH in provider only), DEP-002, DEP-003 |
| TM-41 Repo/secret hygiene before public release | LOW | SEC-01..04 |
| TM-42 Software-keystore key theft from host memory/disk | LOW | none; control: argon2id + AES-256-GCM envelopes, HSM/KMS options (accepted residual since 1.0) |

## UNASSESSED (no one looked; not counted as threats)

CRL generation integrity/DoS; dns-01 resolver trust; XCEP policy when no authenticator is configured (`internal/xcep/server.go:63-64`) and XCEP template policy depth; CT monitor; bulk reissue and imported-certificate trust; commercial CA adapters; OIDC JWKS / SAML metadata fetch origin; per-id tenant probes on credentials, connectors, notifications, targets, inventory sources, SCEP challenges; leaf-escrow and BYOK export under dual control; jwt/oidc live tests; IaC (input file absent); govulncheck on `sdk/` and `plugins/`.

# Completion Manifest

## Files produced
- `docs/security/THREAT_MODEL_FINDINGS_2026-10-09.md` — 3 GAP findings in schema, threat-to-finding map for the other 41, unassessed list — ~120 lines

## Files modified
- `docs/sdlc/phase-3-design/THREAT_MODEL.md` — version 1.1; appended §8 "2026-10-09 Deep-Audit Addendum" (DFD, trust boundaries, STRIDE matrix, threat register, mitigations, archetypes, stale-doc flags). Sections 1-7 (1.0 history) left untouched.

## Decisions made
- ACME CRITICAL mapped to OWASP-A04-001 rather than re-raised — it landed in a file before this phase.
- Severities inherited from findings; elevated only on a DFD-visible chain (TM-09: A02-4 + A01S-4; TM-21: via LLM-001 MCP read path).
- TM-04 kept HIGH (per A01S-3) although it yields a CA private key; its precondition is an admin credential and MULTI_TENANCY on.

## Known issues / deferred
- TM-08 is code-read only; a live probe (custom role with user.manage → PATCH own user) should confirm it before it is fixed.
- IaC_FINDINGS was not present; re-run the IaC STRIDE rows when it lands.

## Verify result
- PASS — every CRITICAL/HIGH threat in §8.5 has a non-empty mitigation in §8.6; no placeholder markers in either file — evidence: `docs/sdlc/phase-3-design/THREAT_MODEL.md`

## Memory written
- None — nothing durable beyond these files

## Model tier: large — medium context used

Maker: threat-modeler
Verifier: attack-chainer (consumes preconditions/yields) and the coordinator

## Ready for: attack-chainer

threat-model done
