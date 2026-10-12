# Attack Chain Analysis: kryptkeeper, 2026-10-09 (--deep)

**Input findings:** 103 REAL after deduplication (grouped LOW items counted once), across 8 categories (semgrep, dependency, secrets, owasp-web A01/A02/A04/A07/A08/A10, owasp-llm, cloud, iac, threat-model). UNVERIFIED items are used only where marked.
**Chains found:** 19 (9 CRITICAL, 7 HIGH, 3 MEDIUM). CRITICAL by status: 3 VERIFIED, 5 PLAUSIBLE, 1 UNVERIFIED.
**Reachability gate:** there is no `docs/reviews/DEAD_CODE_FINDINGS_*`, so every code finding is `reachable: true` and no severity was lowered. DEP-004..DEP-010 are excluded from chains because the dependency auditor marked them NOT REACHABLE. DEP-001/002 (Terraform provider, local plugin channel only) appear in no chain.

## Executive summary

Three paths need **no prior foothold, or only a routine credential**, and end in trust compromise:
1. Anyone who can reach `/acme/` gets a serverAuth certificate for any DNS name, IP or SPIFFE URI from the default CA (CHAIN-01). This holds in the default config whenever the CA engine is on.
2. Any **single** pki-admin can take every CA private key and the global SSH-CA key, **whether or not key dual control is enabled** (CHAIN-02).
3. With MULTI_TENANCY on, any tenant admin can take over every other tenant and export their CA keys (CHAIN-03).

Several entry points end at CHAIN-02's key-egress step: a sniffed bootstrap token (Terraform plain HTTP), a CI/registry compromise, OIDC email linking, a weak HS256 secret, and (UNVERIFIED) custom-role self-escalation. Fixing key egress (A2A7-001, with dual control on by default and A07-4) breaks the most chains. The SSH CA has no principal policy (A01S-4), so any certificate.issue holder, which includes every OIDC user in oidc mode, can mint `root` SSH certificates for the whole fleet.

## Canonical IDs (supplement duplicates = one finding, two confirmations)

| Canonical | Also reported as |
|---|---|
| A01-001 | A01S-1, TM-03 |
| A01-002 | A01S-2 (adds cross-tenant **issue**), LLM-U1 (now resolved REAL), TM-05 |
| A01-004 / A01-005 | A01S-5 (adds GET /ssh/certificates), LLM-001 / LLM-002 (MCP path), TM-21 |
| A2A7-001 | A02-5 (also notes key dual control is **off by default**: key_dual_control.go:58-61), TM-20 |
| A2A7-002 | A02-2 |
| A2A7-003 | A07-5 |
| A2A7-005 | A07-1 |
| A2A7-006 | A07-3 |
| A2A7-008 | A07-2 |
| OWASP-004 | A02-1 |
| OWASP-A04-001 | A04-1 (supplement), TM-01 |
| OWASP-A10-001 | A10-1, TM-02 |
| OWASP-A10-002 | A10-2 |
| A07-4 | LLM-006 is the same class (separation of duties enforced per identity, not per human) |
| SEMGREP "DEP-001" (stdlib) | DEPENDENCY DEP-003 (same 11 stdlib CVEs). Written as **SG-DEP-001** below so it is not confused with DEPENDENCY DEP-001 (grpc in the provider) |

TM-xx entries are mappings, not findings. The exceptions are TM-08, TM-43 and TM-44, which are GAP findings.

## Entry points and the flags they depend on

| Entry | Default config? |
|---|---|
| Unauthenticated network to protocol mux (`/acme/`, `/ocsp`, `/cmp`) | ACME is mounted whenever `APP_CERTIFICATE_PROVIDER=ca` (main.go:535-550). That is the Helm default (values.yaml:70) but not the Terraform module (IAC-001). EAB is off unless `APP_ACME_EAB_REQUIRED=true`. |
| Single pki-admin | Always. `KRYPTKEEPER_KEY_DUAL_CONTROL` defaults to off (key_dual_control.go:58-61). |
| Tenant-scoped admin / viewer | Requires `MULTI_TENANCY=true` |
| IdP user | Requires `AUTH_MODE=oidc`. Every valid token becomes `service-account` = {certificate.read, issue, renew} (auth.go:313-327, authz_custom_roles.go:315-316). |
| MCP agent | Proposal-only. The HTTP transport is opt-in (`KRYPTKEEPER_MCP_TRANSPORT=http`). |
| Plugin author | Requires delivery plugins to be enabled and one admin to install the plugin |
| CI / workflow input | act_runner is live. GitHub Actions is disabled on the repo today. |

---

## CHAIN-01: CRITICAL: Unauthenticated client gets trusted certificates for any name (ACME)
**Status:** VERIFIED (temporary test PASS in OWASP_A03_A08_A10; mount confirmed at main.go:550, CA bound to `defaultCAID` at main.go:535)
**Components:** OWASP-A04-001 (+ OWASP-A04-002 key floor, OWASP-A10-001 identifier handling)
**Entry:** network reach to `/acme/`, no credentials. **Flags:** default whenever the CA engine is on. EAB off (default).
**Reachable:** true. **Final impact:** rogue certificates trusted by relying parties: any DNS, wildcard, IP or SPIFFE URI from the default CA, and RSA-1024 is accepted.

1. **OWASP-A10-001 / A04-001** [CRITICAL]: new-order accepts `{type:"ip", value:"attacker:port"}`. http-01 is validated against the attacker's own server. *Gains:* a valid order.
2. **OWASP-A04-001**: finalize copies CSR DNS, IP and URI SANs and the CN, because `CallerNamesOnly` is unset. *Gains:* a cert such as `DNS=bank.example.com,*.corp.example URI=spiffe://prod.example/ns/admin`.
3. **OWASP-A04-002** [MEDIUM]: no key-strength floor, so the cert can carry a weak key, which also lets third parties factor it and reuse it.
4. *Impact:* MITM any TLS service or SPIFFE workload that trusts the default CA. Revocation does not help, because the attacker can re-order without limit (30 req/min per IP).

Not chained with SEMGREP-012: ACME issues from the default CA, and the OCSP fallback answers from that CA's own revocation store, so a revoked ACME cert reports `revoked`.
**Cheapest break:** in finalize, refuse a CSR whose SAN set is not exactly the order's dns identifiers, and set `CallerNamesOnly: true`. Then make EAB the default.

## CHAIN-02: CRITICAL: One admin takes every CA private key and the SSH-CA key, with or without dual control
**Status:** VERIFIED (A2A7-001 proven by code read and a temporary test. handlers_backup.go:44 and handlers_key_escrow.go:33 check only `isAdminRole`. A07-4 is code-traced.)
**Components:** A2A7-001 → (A07-4) → A01S-4 (optional) → CHAIN-01-class impact
**Entry:** any single pki-admin, including a stolen or forged one (see CHAIN-05/07/08/09). **Flags:** default (dual control off). Also works with `KRYPTKEEPER_KEY_DUAL_CONTROL=true`.
**Final impact:** CA private keys and the global `ssh-ca` key in plaintext. That allows offline issuance of trusted certs and SSH user certs for `root` on every host that trusts the SSH CA.

1. Dual control off (default): `POST /keys/{id}/export` with one admin's passphrase. This is admin capability by design, and the design (D-051, FR-P50) relies on dual control, which ships off.
2. Dual control on: **A2A7-001** [HIGH] `POST /admin/backup` (every extractable key) or `/keys/escrow`, where one body supplies both custodian passphrases. *Gains:* plaintext key material.
3. Alternatively, **A07-4** [MEDIUM]: mint an API key with a fresh free-text `principal_id` and role pki-admin, then approve your own export proposal (proposer ≠ approver compares IDs only).
4. *Impact:* with the CA key, sign anything offline. No audit trail exists for the issuance.

**Cheapest break:** route `/admin/backup` and `/keys/escrow` through `KeyDualControl`, and turn dual control on by default. A07-4 has to be fixed too (canonical human identity), or the second path stays open.

## CHAIN-03: CRITICAL: Tenant admin takes over every tenant and exports other tenants' CA keys (MULTI_TENANCY)
**Status:** VERIFIED (live hub, two independent passes)
**Components:** A01-001 → A01-006 / A01S-6 → A01S-3 → A2A7-001
**Entry:** pki-admin in any one tenant. **Flags:** `MULTI_TENANCY=true`. Dual control off (default).
**Final impact:** cross-tenant takeover. Every tenant's CA key and the shared SSH-CA key are exportable.

1. **A01-001** [CRITICAL]: `POST /api-keys {"role":"pki-admin","tenant":""}` mints a default-tenant (global) admin key (handlers_auth.go:335 passes `req.Tenant` through). *Gains:* unscoped admin.
2. **A01-006 / A01S-6** [MEDIUM]: change global config, credentials and delivery plugins, and delete users in other tenants.
3. **A01S-3** [HIGH]: `POST /keys/key-<other tenant CA>/export` returns that tenant's root CA key. The key store has no tenant reference at all (no match in handlers_keys.go). This step works **without** step 1.
4. If dual control is on: **A2A7-001** backup takes all keys in one call.

**Cheapest break:** A01-001 (refuse `req.Tenant` ≠ the caller's tenant) closes the takeover. A01S-3 is a separate 1-hop path to key theft and needs key-to-CA tenant mapping. Fix both.

## CHAIN-04: CRITICAL: IdP user mints `root` SSH certificates and any-name TLS certificates (AUTH_MODE=oidc)
**Status:** PLAUSIBLE. The role mapping is confirmed in code (auth.go:313-327 → service-account; authz_custom_roles.go:316 grants certificate.issue). The SSH step is live-verified for pki-operator. The oidc path itself was not live-tested.
**Components:** A02-4 → A01S-4 → SUP-A04-3 (+ OWASP-A04-002)
**Entry:** any account at the IdP (empty `APP_OIDC_AUDIENCE`/`ISSUER`), or any user the IdP issues tokens to for this audience. **Flags:** `AUTH_MODE=oidc`.
**Final impact:** fleet SSH root across tenants (one global SSH CA), and rogue TLS certs.

1. **A02-4** [MEDIUM → HIGH with a public IdP]: aud and iss are unchecked when unset. *Gains:* `service-account` principal.
2. **A01S-4** [HIGH]: `POST /ssh/certificates {"principals":["root"]}` is signed with no template or principal policy. *Gains:* a user cert valid for root on every host trusting the SSH CA.
3. **SUP-A04-3** [MEDIUM]: API issuance takes SANs from the CSR and templates cannot restrict names. *Gains:* any-name TLS cert from any CA the principal can reach.

**Cheapest break:** stop mapping jwt/oidc tokens to an issuing role by default (map to viewer unless a role claim is configured). This breaks both variants. Requiring aud/iss at startup closes only the "any IdP account" variant. A01S-4's principal allowlist is the defence in depth.

## CHAIN-05: CRITICAL: Admin credential captured in transit → key egress
**Status:** PLAUSIBLE (each hop verified by code or IaC read; no live MITM)
**Components:** (a) IAC-001 → CHAIN-02; (b) IAC-014 → IAC-005 → CHAIN-02; (c) OWASP-004 → A2A7-003 → CHAIN-02; variant IAC-002 → IAC-003
**Entry:** a network position on the operator↔hub path, or a compromised pod in the cluster.
**Final impact:** CA private keys (via CHAIN-02).

- (a) **Terraform module (default):** **IAC-001** [HIGH] plain HTTP on a public EIP with `AUTH_MODE=bootstrap`, so the attacker sniffs `APP_BOOTSTRAP_TOKEN` (super-admin, cannot be disabled: A07-6). That token is admin, which leads to `/admin/backup` or `/keys/export`. Variant: **IAC-002** (state file) gives the token, and **IAC-003** makes the token *also* the keystore passphrase, so a snapshot of the volume can be decrypted offline with no API call.
- (b) **Helm:** **IAC-005** probes crash-loop under TLS, so an operator sets `KRYPTKEEPER_TLS_DISABLE=true`. Then **IAC-014** (no NetworkPolicy) lets any compromised pod sniff admin tokens.
- (c) **Native TLS, no proxy:** **OWASP-004** issues `kk_token` without `Secure`, so an induced `http://` request leaks the session. **A2A7-003** means logout never revokes it and refresh extends it indefinitely.

Not chained: an SSRF to IMDS that reads the Secrets Manager values. The Terraform instance has `http_tokens = "required"` (compute/main.tf:144), and every SSRF sink found is GET or POST only, so none can mint an IMDSv2 token.
**Cheapest break:** IAC-001: ship TLS in the Terraform module (`APP_CERTIFICATE_PROVIDER=ca` + cert, or an ALB). This is the default-config variant. CHAIN-02's fix contains all three variants.

## CHAIN-06: CRITICAL: CI or registry compromise → code running as the hub → CA keys and the cloud KMS account
**Status:** PLAUSIBLE (IaC read only)
**Components:** DEP-011 / IAC-008 → IAC-007 / IAC-016 → IAC-004 → CLOUD-002 (+ IAC-006, IAC-017)
**Entry:** a CI/workflow input: a mutable third-party action tag, the runner base image, a malicious dependency in a test job, or repo-write dispatch.
**Final impact:** attacker code in the hub with the keystore passphrase, bootstrap token and DB password in env. That yields CA keys, plus signing with any KMS key in the AWS account (CLOUD-002).

1. **DEP-011** (actions pinned by tag) / **IAC-008** (`catthehacker/ubuntu:act-latest`) → code in CI jobs.
2. **IAC-007** (the self-hosted forge default token can write) / **IAC-016** (package-write at workflow level) → push `ghcr.io/.../kryptkeeper:latest`.
3. **IAC-004** [MEDIUM]: Terraform runs `:latest` with no digest and no `cosign verify` on the next restart.
4. **CLOUD-002** [MEDIUM]: the hub role can `kms:Sign` and `kms:ScheduleKeyDeletion` on every untagged key in the account.

Side paths: **IAC-006** (dispatch input injected into the prod deploy job → `DEPLOY_CMD_PRODUCTION`). **IAC-008 → IAC-017** (COSIGN_KEY on runner disk → attacker-signed releases that pass key-based verification).
**Cheapest break:** IAC-004: deploy by digest and add `cosign verify` (keyless identity) in `ExecStartPre`. That breaks every registry-side path. IAC-006 needs its own `env:` indirection.

## CHAIN-07: CRITICAL: IdP user with a mutable email takes a provisioned admin account
**Status:** PLAUSIBLE (conditional on IdP behaviour; code path read end to end)
**Components:** A2A7-006 → CHAIN-02 (MULTI_TENANCY: → A01-001 / A01S-3)
**Entry:** IdP user who can set an unverified email. **Flags:** OIDC login enabled, and the target pki-admin has not yet logged in through OIDC.
1. **A2A7-006** [MEDIUM]: callback falls back to the `email` claim with no `email_verified` check and permanently links `(iss,sub)` to the account. *Gains:* pki-admin.
2. Then CHAIN-02 (keys), or CHAIN-03 when multi-tenant.
**Cheapest break:** require `email_verified == true` before email fallback.

## CHAIN-08: CRITICAL: Any session holder forges a pki-admin session (weak HS256 secret)
**Status:** PLAUSIBLE (conditional on an operator-chosen short secret; nothing enforces a minimum)
**Components:** A02-3 (+ A2A7-009 no length floor) → CHAIN-02
**Entry:** any issued session JWT, for example a viewer's. **Flags:** short `APP_AUTH_LOGIN_SIGNING_SECRET` or `APP_JWT_HS256_SECRET`.
1. **A02-3** [MEDIUM]: brute-force the HMAC offline and mint `role: pki-admin`.
2. Then CHAIN-02.
Related: **A2A7-002** turns env/config read into an offline-cracked admin password at about 3M guesses/s/core.
**Cheapest break:** refuse to start with an HS256 secret under 32 bytes.

## CHAIN-09: CRITICAL (UNVERIFIED): Custom role with `user.manage` grants itself pki-admin
**Status:** UNVERIFIED. TM-08 is code-read only and has not been live-probed.
**Components:** TM-08 → CHAIN-02 (MULTI_TENANCY: → A01-001)
**Entry:** a user on a delegated custom role. **Flags:** custom-role store (DB mode).
1. **TM-08** [HIGH if real]: `PATCH /users/<self> {"role":"pki-admin"}` or `PUT /roles/<own>` with the full vocabulary. The gate for both is `user.manage` itself.
2. Then CHAIN-02 or CHAIN-03.
**Cheapest break:** a grantor must hold every permission it grants, and assigning `pki-admin` requires pki-admin. Confirm with a live probe first.

## CHAIN-10: HIGH: pki-operator mints fleet-wide `root` SSH certificates
**Status:** VERIFIED (live: operator got `["root","admin"]`, 201)
**Components:** A01S-4. A single finding, so it keeps HIGH. Its impact is fleet SSH root and it crosses tenants because the SSH CA is global (A01S-5: GET /ssh/certificates is also unscoped).
**Entry:** pki-operator, or any certificate.issue holder. **Flags:** default.
**Cheapest break:** a per-role or per-template allowed-principals list enforced in handlers_ssh_certs.go.

## CHAIN-11: HIGH: Injected MCP agent drives cross-tenant revocation or issuance through a same-tenant approver
**Status:** PLAUSIBLE. A01-002 was verified live (cross-tenant revoke 200, plus cross-tenant issue in A01S-2). The injection step was traced in code only.
**Components:** LLM-003 → LLM-001 / A01-004 → LLM-005 → A01-002 → A01-003 (+ LLM-006 / A07-4)
**Entry:** an unauthenticated attacker who controls a TLS endpoint in a scanned range (cert CN/SAN), or any HTTP client (user_agent in audit). Variant: **LLM-004** DNS rebinding to the MCP HTTP transport (opt-in) gives direct tool access. **Flags:** `MULTI_TENANCY=true` for the cross-tenant part. Human approval required.
**Final impact:** revocation tampering (bulk_revoke of another tenant's CA), or issuance from another tenant's CA.
1. **LLM-003** [MEDIUM]: an injected string in tool output steers the agent.
2. **LLM-001 / A01-004** [HIGH / MEDIUM]: the agent reads the cross-tenant audit log to learn who approves and when.
3. The agent proposes `bulk_revoke` or `issue` against a foreign CA with a persuasive rationale. **LLM-005**: the proposal is unbounded, so it can bury the queue.
4. **A01-002** [HIGH]: the proposal is stamped with the proposer's tenant, so a same-tenant approver can decide it, and the executor acts on any CA or fingerprint.
5. **A01-003** [MEDIUM]: concurrent approvals execute it several times.
Without MULTI_TENANCY the same path is approver social engineering against your own CA (MEDIUM).
**Cheapest break:** A01-002: in `executePendingAction`, check that the target CA or cert belongs to `action.Tenant`.

## CHAIN-12: HIGH: Unauthenticated OCSP lies keep a revoked certificate alive (multi-CA)
**Status:** PLAUSIBLE (deterministic code path, confirmed by two passes; not run against a hub)
**Components:** SEMGREP-012 + SEMGREP-013 (+ SEMGREP-014 for ACME revoke during a DB error, UNVERIFIED)
**Entry:** network reach to `/ocsp`. **Flags:** more than one CA. The target cert was issued by a non-default CA.
1. **SEMGREP-012** [MEDIUM]: a bogus IssuerKeyHash falls back to the default CA, which signs `good`. The response is cached for 24h under the serial alone. A legitimate query for the revoked serial then gets a response that soft-fail clients ignore, so they accept the cert. The attacker re-poisons after every `InvalidateCache`.
2. **SEMGREP-013** [LOW]: on a CA-list read error, a correctly signed `good` is produced for a revoked cert.
Escalated above MEDIUM because it is unauthenticated and defeats incident response (revocation) for any attacker holding a revoked leaf's key.
**Cheapest break:** return `unauthorized` when no CA matches the IssuerKeyHash, and key the cache by (issuer hashes, serial).

## CHAIN-13: HIGH: Plugin author gets root on delivery targets
**Status:** PLAUSIBLE (code read)
**Components:** SUP-A08-1 → OWASP-A08-001 (+ A01-003)
**Entry:** a plugin author, plus one admin who installs the plugin. **Flags:** delivery plugins enabled. The deploy account has NOPASSWD sudo.
1. **SUP-A08-1** [MEDIUM]: an unsigned manifest that declares only `hosts_from_credential` is rated Standard tier, so one admin can enable it.
2. **OWASP-A08-001** [MEDIUM]: `["sh","-c","sudo …"]` passes the argv[0] check, giving root on every target the plugin delivers to, along with the private keys deployed there.
**Cheapest break:** run non-elevated plugin execution under an account with no sudo rights.

## CHAIN-14: HIGH: Unauthenticated SSRF into the internal network (ACME http-01)
**Status:** VERIFIED for the internal GET (a temporary test reached `/latest/meta-data/...` through a redirect). The credential theft extension is not chained (IMDSv2 required in Terraform).
**Components:** OWASP-A10-001 (+ SUP-A03-2 log injection)
**Entry:** unauthenticated. **Flags:** default when the CA engine is on.
**Impact:** blind GET to any internal host, port or path. The status leaks through the authz state, and 512 bytes of the response go to the hub log. An IMDSv1 host with readable logs would leak credentials (UNVERIFIED, not the Terraform default).
**Cheapest break:** the same identifier validation as CHAIN-01 (dns only, no port), plus port-80-only dialing with a private-range dial guard.

## CHAIN-15: HIGH: Operator turns stored integration credentials and the hub's network position into exfiltration
**Status:** PLAUSIBLE
**Components:** SEMGREP-002 + SEMGREP-001 + OWASP-A10-002 (+ CLOUD-007, SEMGREP-007 UNVERIFIED)
**Entry:** a pki-operator, discovery-operator or notification-operator, or an API key with `ops:write`. **Flags:** default.
1. **SEMGREP-002** [MEDIUM]: point an inventory source's base URL at an attacker host. The stored `credential_ref` is sent as the auth header.
2. **OWASP-A10-002 / SEMGREP-001** [MEDIUM]: port-scan internal hosts through the error oracle and POST with chosen headers to internal APIs.
Impact: internal network access, plus theft of third-party credentials the hub holds.
**Cheapest break:** one shared egress dialer guard (no private, loopback or link-local addresses; re-checked on redirect) and credentials bound to their approved host.

## CHAIN-16: HIGH: Authenticated enrolment paths issue any name
**Status:** PLAUSIBLE (code read, two passes)
**Components:** SUP-A04-2 / SUP-A04-3 + OWASP-A04-002
**Entry:** any CMP client holding the shared `KRYPTKEEPER_CMP_SECRET`, or any certificate.issue holder (including oidc service-accounts, see CHAIN-04).
**Impact:** 1-year clientAuth or serverAuth certificates for arbitrary SANs and subjects, so the attacker can impersonate any mTLS client or server that trusts the CA.
**Cheapest break:** set `CallerNamesOnly` and Subject on CMP and API issuance, and add a SAN allowlist to templates.

## CHAIN-17: MEDIUM: Recon and covering tracks (supports CHAIN-11/03)
**Components:** A01-004 / LLM-001, A01-005 / LLM-002, A01-007, CLOUD-001, OWASP-001, OWASP-002, TM-43 (UNVERIFIED)
**Entry:** a tenant viewer or the mcp-agent token (MULTI_TENANCY for the cross-tenant parts). The attacker learns other tenants' certificates, CAs, approver identities and timing, and cloud KMS account IDs. **OWASP-001/002** then forge the source IP and tenant on audit rows.
**Cheapest break:** tenant predicate plus `audit.read` permission on `/audit`.

## CHAIN-18: MEDIUM: cert-manager connector MITM (opt-in)
**Components:** SEMGREP-003 → IAC-015
**Entry:** an on-path attacker when `KRYPTKEEPER_K8S_SKIP_VERIFY=true`. The attacker steals the k8s SA bearer token and forges cert-manager responses. A compromised issuer pod can write certificates cluster-wide (IAC-015).
**Cheapest break:** remove the env bypass and use CA or SPKI pinning.

## CHAIN-19: MEDIUM: Unauthenticated availability attacks on auth and protocol endpoints
**Components:** A2A7-004 (oidc: 2 IdP fetches per forged token, under a global lock), OWASP-A04-003 / -004 / -005, SG-DEP-001 / DEP-003 (only binaries built with go1.27.0-1.27.1), CLOUD-001 → CLOUD-006
**Impact:** OIDC authentication serialized or IdP rate-limited, ACME nonces flushed, CMP CPU amplified. The cloud-inventory case needs authentication.
**Cheapest break:** cool down forced JWKS refreshes and pin the release toolchain.

---

## Fix leverage (canonical findings ranked by the number of chains they appear in)

| Rank | Finding | Chains | Why |
|---|---|---|---|
| 1 | **A2A7-001** + dual control off by default | 02, 03, 05, 07, 08, 09 (6) | The shared key-egress terminal step. Every admin-level compromise ends here. |
| 2 | **A01-001** | 03, 07, 09 (3, MT) | One line turns a tenant admin into a global admin |
| 3 | **A01S-4** | 02, 04, 10 (3) | Every issuer becomes fleet SSH root. Shared SSH CA. |
| 4 | **OWASP-A04-001** (identifier validation) | 01, 14 (2) | Unauthenticated, default config. The same fix closes the SSRF identifier path. |
| 5 | **A01S-3** / **A07-4** (tie) | 03, 07 / 02, 11 (2 each) | A01S-3 is 1-hop cross-tenant CA key theft. A07-4 defeats dual control even once it is enabled. |

Close runners-up: SUP-A04-3 (04, 16), A01-002 (11, live-verified), IAC-004 (06), IAC-001 (05).

## Single-domain CRITICAL/HIGH findings outside any chain
None. Every REAL CRITICAL or HIGH finding is in at least one chain above. DEP-001 (grpc in the Terraform provider, HIGH) needs a local foothold on the machine running `terraform` and leads to no hub asset, so it is fixed independently (bump grpc to 1.83.1 or later).

## Task checklist (kept here because the write-scope is this file only)
- [x] Loaded all 14 findings files. `final-report.md` is absent, so Phase 6 was skipped. No dead-code report exists.
- [x] Canonical ID table built. Supplements merged.
- [x] yields → preconditions matching per chain, and the flags stated
- [x] Key evidence re-read in code: handlers_keys.go (no tenant), handlers_backup.go:44 and handlers_key_escrow.go:33 (admin only), key_dual_control.go:58-61 (default off), auth.go:313-327 and authz_custom_roles.go:316 (oidc → issuer), handlers_auth.go:335 (req.Tenant passed through), main.go:535/550 (ACME on defaultCAID), compute/main.tf:144 (IMDSv2 required)
- [x] Narrative for every CRITICAL chain, and the cheapest break for every chain
- [x] Finding-ID existence check (see Verify result)

# Completion Manifest

## Files produced
- `docs/security/ATTACK_CHAINS_2026-10-09.md`: 19 chains, fix-leverage ranking, canonical ID map

## Files modified
- None

## Decisions made
- CHAIN-01 is not joined with SEMGREP-012, because the ACME CA is the OCSP default CA, so its revocations answer `revoked`.
- SSRF → IMDS → Secrets Manager was rejected for Terraform (IMDSv2 `required`; no PUT-capable sink).
- A01S-4 is kept HIGH as a single finding (CHAIN-10). It is CRITICAL only inside CHAIN-04.
- CHAIN-12 is escalated to HIGH: unauthenticated, and it defeats revocation.
- TM-08 is included only as UNVERIFIED (CHAIN-09).

## Known issues / deferred
- The oidc paths (CHAIN-04/07) and the MCP injection (CHAIN-11) are not live-tested.
- UNASSESSED areas from the threat model (CRL, dns-01, XCEP without an authenticator, commercial CA adapters) could add chains.

## Verify result
- PASS: every finding ID cited in this file exists in a 2026-10-09 source findings file (grep loop). Evidence: `docs/security/ATTACK_CHAINS_2026-10-09.md`

## Memory written
- None. Nothing durable beyond this file.
## Model tier: large, context used: medium

Maker: attack-chainer
Verifier: advisor review (separate model). The Challenger gate is still needed from the coordinator.

## Ready for: security-auditor resume (final report)

attack-chains done
