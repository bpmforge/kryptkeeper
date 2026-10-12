# Kryptkeeper security audit — final report (--deep, 2026-10-09)

**Scope:** the whole repository at `0236b86` (Go hub `cmd/` + `internal/`,
`sdk/`, `plugins/`, React UI `ui/`, Terraform provider, `deploy/terraform`,
Helm charts, Dockerfiles, CI workflows), plus full git history for secrets.
**Why now:** the repo is private and goes public only after the basic features
are validated and the code-health and security scans are run and their
findings fixed (the owner, 2026-10-09). This report is the security half of that
gate.

## 1. Verdict

**Not ready for a public release.** After deduplication and the challenger
review (§7): **3 CRITICAL** (one default-config, two only with multi-tenancy)
and **9 HIGH**. Three of the 9 CRITICAL attack chains are
verified by test or against a live hub:

1. **Default config, no credentials:** anyone who can reach `/acme/` gets a
   certificate from the default CA for any DNS name, IP address or SPIFFE ID
   (OWASP-A04-001, proven by test).
2. **One admin:** a single pki-admin can take every CA private key and the
   global SSH-CA key, with or without key dual control (A2A7-001, A07-4).
3. **Multi-tenancy on:** any tenant admin can mint a pki-admin API key in any
   other tenant and export other tenants' CA keys (A01-001, A01S-3, proven
   live).

The good news: no live secrets anywhere in the code or git history (gitleaks
plus a blob-level scan), no dependency on CISA KEV, no reachable HIGH/CRITICAL
CVE in the hub itself, the new write gate (W20-26/27) held against path
normalisation and method tricks, and most protocol cryptography (ACME JWS, EST,
SCEP challenges, WSTEP/XCEP, CMP protection) checked out clean.

**Status update (fix groups merged).** The verdict above is the audit-time verdict at `0236b86`. Since then FG-1
through FG-5 and FG-7 through FG-14 and the multi-tenancy experimental gate (D-123) are merged to `main` (see the
Status column of §5). The 3 CRITICAL are closed or gated: OWASP-A04-001 fixed in FG-1; A01-001 and A01S-3 are
multi-tenancy only, deferred to FG-6a/6b (v0.10), and `MULTI_TENANCY=true` is refused without
`KRYPTKEEPER_MULTI_TENANCY_EXPERIMENTAL=accept-risk`. Residual risk is tracked in
`OWASP_TRACKER.md` and `THREAT_MODEL.md` §8.5/§8.10. The findings tables in §3 are unchanged audit-time text.

## 2. Coverage

| Specialist | Output | Engine / method | Confidence |
|---|---|---|---|
| SAST | SEMGREP_FINDINGS | Opengrep 1.30.2 (signature-verified) with bpm-rulepacks only (80 rules applied, 713 files), ast-grep 0.45.3 (13 TS rules), govulncheck, manual sweeps | — |
| Secrets | SECRETS_FINDINGS | Blob scan of 11,679 blobs / 1,633 commits / all refs; gitleaks 8.30.1 over all history (26 hits, all FP) | — |
| Dependencies | DEPENDENCY_FINDINGS | govulncheck per module, npm audit, syft SBOM (591 components, `sbom_2026-10-09.cdx.json`), grype (KEV 0) | — |
| OWASP Web | OWASP_WEB, OWASP_A01 (+supplement), OWASP_A02_A07 (+supplement), OWASP_A03_A08_A10 (+supplement) | Code tracing, temp Go tests, live hubs (MULTI_TENANCY on, two tenants) | A01 7, A02 7, A03 7, A04 7–8, A05 7, A06 7, A07 7–8, A08 7, A09 7, A10 6–7 |
| OWASP LLM (MCP server) | LLM_FINDINGS | Code reading, tests | — |
| Cloud (AWS/GCP/Azure KMS, inventory) | CLOUD_FINDINGS | Code reading (no real-cloud UAT exists) | — |
| IaC / CI | IaC_FINDINGS | Manual review against Checkov/KICS/Trivy rule sets (none installed) | — |
| Threat model | THREAT_MODEL_FINDINGS, docs/sdlc/phase-3-design/THREAT_MODEL.md §8 | STRIDE, 44 threats | — |
| Attack chains | ATTACK_CHAINS | 19 chains from 103 deduplicated findings | — |

Every OWASP category reached the confidence target of 7 except A10 in one of
its two passes (6: commercial CA adapters and the CT monitor were not traced).
Each "supplement" is an independent second pass; matching findings are one
finding with two confirmations (canonical IDs in ATTACK_CHAINS §Canonical IDs).

**Not covered:** real cloud KMS (no accounts), F5/Citrix devices, Checkov/KICS
runs, deep goxmldsig signature-wrapping analysis, wazero memory/time limits,
the commercial CA adapters and CT monitor for SSRF.

## 3. Findings (deduplicated) by severity

Counts are canonical findings (LOW groups counted once), after the challenger
review: **CRITICAL 3, HIGH 9, MEDIUM ~38, LOW ~45.** Severity changes made by
the challenger are marked ⚖. MT = only with `MULTI_TENANCY=true`; OIDC = only with
`AUTH_MODE=oidc`.

### CRITICAL

| ID | Finding | Where | Proof | Scope |
|---|---|---|---|---|
| OWASP-A04-001 | ACME finalize never sets `CallerNamesOnly`, so CSR DNS/IP/URI SANs and Subject are issued; newOrder accepts any identifier type, so an `ip` order validated against the attacker's host yields any DNS names | internal/acme/server.go:350-365, 626-640; internal/ca/engine.go:704-716 | test + coordinator code read | default config (EAB off by default) |
| A01-001 | Tenant pki-admin mints a pki-admin API key in any tenant (body `tenant` trusted); GET/DELETE /api-keys not tenant-filtered | internal/bootstrap/handlers_auth.go:317-335 | live, three times | MT |
| A01S-3 ⚖ | Key store has no tenant scope: a tenant admin exported another tenant's root CA key and can export the global `ssh-ca` key (raised from HIGH: same impact class as A01-001) | handlers_keys.go:149-160, 273-335 | live | MT |

### HIGH

| ID | Finding | Where | Proof | Scope |
|---|---|---|---|---|
| A2A7-001 | `/admin/backup` and `/keys/escrow` export private keys past key dual control (export alone honours it); dual control is **off by default** | handlers_backup.go:36-85; handlers_key_escrow.go:42-80; key_dual_control.go:58-61 | test + code | default |
| A07-4 ⚖ | Proposer ≠ approver compares principal IDs; an admin mints API keys with any `principal_id` and approves their own proposals (also LLM-006: operator approves what their agent proposed). The supplement rated it MEDIUM; HIGH because it defeats dual control once that is on | handlers_pending_actions.go:164; handlers_auth.go:335 | code | default |
| A01-002 | Approved actions run against other tenants' certificates/CAs (revoke, bulk revoke, issue) | handlers_pending_actions.go:72-79,123-131; pending_action_exec.go:37-130 | live (revoke and issue) | MT |
| A01S-4 | SSH certificates: any principals (`root`), no template, one global SSH CA; every OIDC token is a service-account with certificate.issue | handlers_ssh_certs.go:150-156,251-257; auth.go:312-327 | live (operator) | default; worse with OIDC |
| A02-4 ⚖ | OIDC with empty audience/issuer accepts any token from the IdP as a service-account (certificate issue/renew); `nbf` never checked. HIGH with a public IdP, MEDIUM with a private one | auth_jwks.go:75-86; auth_hs256.go:66-78; auth.go:316-327 | code | OIDC |
| TM-08 | `user.manage` is admin-equivalent: PATCH /users/{id} sets any role (pki-admin); PUT /roles/{name} adds any permission; no "grant only what you hold" | handlers_users.go:102-112; authz_custom_roles_handlers.go:57-67, 196-203 | code (coordinator confirmed) | custom role with user.manage |
| IAC-001 | Terraform deploy serves plain HTTP on a public Elastic IP (bootstrap token in cleartext). Ingress is limited to the operator CIDRs the module requires, so HIGH is borderline | deploy/terraform/modules/compute/templates/user_data.sh.tpl:125; compute/main.tf:141 | IaC + code | Terraform users |
| A01-006w ⚖ | Write half of A01-006: a tenant admin rewrites the GLOBAL config (including `sso.oidc_jwks_json`), credentials and delivery plugins (raised from MEDIUM) | handlers_config.go; handlers_credentials.go; handlers_delivery_plugins.go | live (credentials listing); code | MT |
| A2A7-006 ⚖ | OIDC login links an account by `email` without `email_verified`, permanently (raised from MEDIUM when OIDC login is on) | auth_oidc_login.go:496-555 | code | OIDC login |

### MEDIUM (grouped; full rows in the source files)

- **Lowered by the challenger ⚖:** OWASP-A10-001 ACME http-01 SSRF (blind, GET-only, body only in the server log; was HIGH); LLM-001/A01-004 `/audit` readable by any principal (session_id is a client header, not a credential; was HIGH; cross-tenant part MT); DEP-001 Terraform provider grpc v1.79.2/x/net v0.48.0 (needs a local foothold; was HIGH).

- **Tenancy (MT):** search/CBOM/SSH-cert list cross-tenant (A01-005, A01S-5, LLM-002); admin resources unscoped (credentials, keys list, config, ceremonies, plugins: A01-006); users shared (A01S-6); approval executes N times under concurrent approvals (A01-003, **default config**).
- **AuthN:** login password is HMAC not a KDF (A2A7-002); logout revokes nothing and refresh extends forever with the login-time role (A2A7-003); forged `kid` floods the IdP (A2A7-004); HS256 secrets need only be non-empty (A02-3); SAML RelayState `/\host` redirect and no InResponseTo/replay cache (A2A7-005/008); cookie `Secure` only from X-Forwarded-Proto (OWASP-004).
- **SSRF:** notification webhooks (SEMGREP-001), inventory-source base URL (SEMGREP-002), ACME connector health probe as a port scanner (A10-002).
- **Issuance policy:** CMP issues any CSR names under one shared secret (SUP-A04-2); templates cannot restrict names and API issuance takes CSR SANs (SUP-A04-3); ACME/CMP accept RSA-1024 (A04-002); OCSP signs "good" from the default CA for unknown issuers and caches by serial (SEMGREP-012/013).
- **Plugins:** `sh -c sudo` gets root without `elevated_exec` (A08-001); `hosts_from_credential` is Standard tier, so one admin enables it (SUP-A08-1).
- **MCP:** HTTP transport has no auth/Origin check or body cap (LLM-004); tool output not marked untrusted (LLM-003); unbounded proposal bodies (LLM-005).
- **Cloud:** key inventory endpoint authn-only and leaks ARNs (CLOUD-001); KMS keys untagged so IAM cannot be scoped (CLOUD-002); GCP/Azure CA keys not HSM-backed (CLOUD-003); k8s connector `SkipVerify` (SEMGREP-003).
- **IaC/CI:** secrets in Terraform state (IAC-002); passphrase defaults to the bootstrap token (IAC-003); `latest` image, no digest (IAC-004); Helm TLS default crash-loops (IAC-005); workflow_dispatch input injection (IAC-006); workflows without `permissions:` (IAC-007); mutable CI image (IAC-008).
- **Supply chain:** local Go 1.27.1 builds carry 11 reachable stdlib CVEs (fixed 1.27.2; CI/release pin 1.26.9); provider x/net (DEP-002); UI dev tools declared as prod deps (DEP-005); react-router-dom advisories (DEP-004, not reachable).

### LOW (examples)

Audit IP from client-controlled X-Forwarded-For and tenant from raw X-Tenant (OWASP-001/002); no CSP/HSTS/frame headers (OWASP-003); agent token logged (SEMGREP-004); bootstrap token `==` compare, no strength, cannot be disabled (A07-6); in-memory agent store `!=` (A07-7); per-IP-only login limit (A07-8); secret-bearing responses lack `no-store`; write gate matches the decoded path (A01S-7, not exploitable today); ACME log injection, nonce-store wipe, http-01 for wildcards; CMP iteration CPU; discovery has no range cap or deny-list; OIDC JWKS redirect to http; WinRM `cmdQuote` (needs credential write); actions not SHA-pinned (DEP-011); lab IPs and a hypervisor token *name* in docs (SEC-01/02); `.gitignore` gaps (SEC-04); no TLS required to Postgres (TM-44); webhook targets stored in plaintext (TM-43).

## 4. Attack chains (from ATTACK_CHAINS_2026-10-09.md)

19 chains: **9 CRITICAL** (3 verified, 5 plausible, 1 unverified), 7 HIGH, 3 MEDIUM.

| Chain | Entry → impact | Findings |
|---|---|---|
| 01 | Unauthenticated → trusted certificates for any name | A04-001, A10-001, A04-002 |
| 02 | One admin → every CA key + SSH-CA key, dual control or not | A2A7-001, A07-4, A01S-4 |
| 03 | Tenant admin → every tenant + their CA keys (MT) | A01-001, A01-006, A01S-6, A01S-3, A2A7-001 |
| 04 | IdP user → fleet `root` SSH + any-name TLS (OIDC) | A02-4, A01S-4, SUP-A04-3 |
| 05 | Admin credential sniffed in transit → key egress | IAC-001/002/003/005, OWASP-004, A2A7-003 |
| 06 | CI or registry compromise → code as the hub → keys | IAC-004/006/007/008, DEP-011 |
| 07 | IdP user with a mutable email → admin account | A2A7-006 |
| 08 | Any session holder + weak HS256 secret → forged admin | A02-3 |
| 09 | Custom role with user.manage → pki-admin | TM-08 |

Ruled out: OCSP lies do not extend chain 01 (ACME certs answer from the right store); SSRF to cloud metadata does not reach Terraform host secrets (IMDSv2 required, no sink sends PUT).

## 5. Remediation plan: fix groups, in order

Each group is one PR (or two where marked), written by a Sonnet agent from a
brief, reviewed, re-verified against a running hub where the finding was
proven live, and merged on green CI.

| # | Fix group | Closes | Sev | Decision needed? | Status |
|---|---|---|---|---|---|
| FG-1 | **ACME issuance**: accept `dns` identifiers only (valid names, wildcard only via dns-01); set CallerNamesOnly + Subject from the order; CSR names must equal the order; http-01 to port 80 only, no redirects off-host, refuse private/loopback/link-local targets; minimum key strength on ACME/CMP; `%q` logging; nonce store LRU | A04-001, A10-001, A04-002, A03-2, A04-004 | CRIT | no | merged (PR #60) |
| FG-2 | **Key egress + separation of duties**: backup, escrow, leaf-escrow and BYOK export through dual control; proposer ≠ approver by human identity (API keys bound to a user; keys minted by the proposer cannot approve); execute only after the compare-and-set decision (no double execution) | A2A7-001, A07-4, LLM-006, A01-003 | HIGH | **yes: dual control default on?** | merged (PR #63) |
| FG-3 | **RBAC escalation + sensitive reads**: grant only roles/permissions you hold (users PATCH, roles PUT, api-keys create); validate role strings; read permissions for /audit, cloud key inventory and other sensitive reads (mcp-agent and viewers per a read table, same shape as the write gate) | TM-08, LLM-001, CLOUD-001 | HIGH | no | merged (PR #71) |
| FG-4 | **SSH CA policy**: allowed principals per role/template, refuse unconfigured; host-cert patterns | A01S-4 | HIGH | **yes: policy shape** | merged (PR #62) |
| FG-5 | **OIDC/JWT hardening**: fatal startup without issuer/audience in oidc mode, `nbf`; HS256 secrets ≥ 32 bytes; bootstrap token constant-time + strength + disable switch; jwt/oidc bearer default role | A02-4, A02-3, A07-6 | HIGH | **yes: bearer-token default role** | merged (PR #64) |
| FG-6a | **Tenancy writes (MT)**: API keys created in the caller's tenant only; key store, credentials, config, ceremonies, plugins scoped; approval targets checked against the action's tenant; users get a tenant | A01-001, A01S-3, A01-002, A01-006, A01S-6 | CRIT/HIGH | **yes: is multi-tenancy in v0.9?** | deferred to v0.10 (multi-tenancy experimental) |
| FG-6b | **Tenancy reads (MT)**: search, CBOM, audit, SSH-cert list, `meta.total` | A01-004/005, A01S-5, A01-007, LLM-002 | MED | same | deferred to v0.10 (multi-tenancy experimental) |
| FG-7 | **Session/login**: Argon2id login hash, logout revokes refresh, refresh re-resolves role, JWKS refetch throttle, `email_verified`, OIDC nonce + state cookie, SAML InResponseTo + replay cache, redirect parsing, cookie Secure on r.TLS, `no-store`, security headers | A2A7-002..008, OWASP-003/004, A02-6 | MED | no | merged (PR #73) |
| FG-8 | **Outbound egress policy**: one hardened HTTP client (private-range block after DNS, redirect policy, timeouts) for webhooks, inventory sources, ACME connector (+ generic errors), OIDC https-only redirects; optional discovery deny-list | SEMGREP-001/002, A10-002, SUP-A10-4, A10-003 | MED | no | merged (PR #67) |
| FG-9 | **Issuance policy**: template SAN/CN allowlists enforced on every path; CMP names bound per client; OCSP answers "unknown" for unknown issuers and caches by (issuer, serial); ACME revoke uses the issuing CA | SUP-A04-2/3, SEMGREP-012/013/014 | MED | no | merged (PR #72) |
| FG-10 | **Plugins + MCP**: block exec of shells/su/pkexec/env without elevated_exec; any network capability is High tier; MCP HTTP auth + Origin/Host + body cap; proposal size cap; tool output wrapped as untrusted | A08-001, SUP-A08-1, LLM-003/004/005 | MED | no | merged (PR #69) |
| FG-11 | **Cloud**: tag KMS keys and document the minimal policy; configurable HSM protection on GCP/Azure; k8s SkipVerify removed or pinned | CLOUD-002/003, SEMGREP-003 | MED | no | merged (PR #68) |
| FG-12 | **IaC/CI**: TLS in the Terraform module, secrets out of state, separate passphrase, digest pins, Helm probes match TLS, workflow input via env, `permissions:` everywhere, SHA-pinned actions and CI image | IAC-001..008, DEP-011 | HIGH/MED | no | merged (PR #66) |
| FG-13 | **Dependencies + hygiene**: provider grpc ≥ 1.83.1 / x/net / x/text; move shadcn/msw to devDependencies; react-router-dom ≥ 7.18.2; local Go 1.27.2; THIRD_PARTY notices (Geist OFL); `.gitignore`; stop logging the agent token | DEP-001/002/004/005, SG-DEP-001, SEC-04, SEMGREP-004 | HIGH/MED | no | merged (PR #65) |
| FG-14 | **Docs truth**: TENANCY_POSTURE, threat model §1 claims (notification encryption, bcrypt), ARCHITECTURE components, OWASP_TRACKER | TM §8.8 | — | no | merged (PR #70) |

Order: FG-1 first (unauthenticated, default config), then FG-2/3/4/5 (the
admin-level and auth chains), then FG-6 (if multi-tenancy ships in v0.9),
then the MEDIUM groups. Every fix that changes auth, crypto or input
behaviour gets a regression test that fails on the old code and, where the
finding was proven live, a re-run of that probe.

## 6. Owner decisions (2026-10-09)

Accepted: key dual control on by default (logged explicit opt-out); jwt/oidc
bearer tokens read-only by default with a claim-to-role mapping; SSH
certificates need per-template allowed principals. **Multi-tenancy ships in
v0.9 as experimental:** the hub refuses `MULTI_TENANCY=true` without an
explicit acknowledgement, logs a warning, the UI and docs label it, and FG-6
is filed for v0.10 (so the two MT-only CRITICALs and the MT HIGHs are
accepted, documented risk for an opt-in experimental mode). Findings that
also hit single-tenant installs (A01-003, A01-004, A2A7-001, A07-4) are fixed
in their own groups.

### The questions as asked

1. **Multi-tenancy in v0.9?** Fixing FG-6 is the largest piece. The alternative is shipping v0.9 with multi-tenancy marked experimental and refused at startup unless explicitly acknowledged, then fixing FG-6 for v0.10.
2. **Key dual control on by default?** Recommended for a PKI product; single-admin installs would then need a second admin (or an explicit opt-out) to export keys.
3. **Bearer-token (AUTH_MODE=jwt/oidc) default role:** today every token is a service-account that can issue. Recommended: read-only by default, with issuing roles granted through a claim-to-role mapping.
4. **SSH principal policy:** per-template allowed principals (recommended), or per-role.

## 7. Challenger gate

`docs/reviews/CHALLENGE_REPORT_security_2026-10-09.md`: score 8/10. All 13
CRITICAL/HIGH rows held up (10 confirmed, 3 overstated, none wrong); both
CRITICALs were reproduced again in fresh temp tests (the A01-001 run also
listed and deleted another tenant's key). Its severity corrections are
applied above (⚖). It also notes ACME is mounted on the main listener in the
compose default and that the ACME attacker needs an HTTP endpoint the hub
can reach.
