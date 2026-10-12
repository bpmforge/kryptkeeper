# Challenge report: security audit final report (2026-10-09)

**Artifact challenged:** `docs/security/final-report.md`, plus the source files it cites.
**Branch:** `kk/security-audit-2026-10-09`. No product code was changed. The two temporary tests below were deleted after they ran.
**Method:** I read the cited code for each CRITICAL and HIGH row (line drift noted where it occurred). I looked for controls the report missed: `authz_write_gate.go`, handler checks one level deeper, config defaults, and deployment defaults. I then wrote and ran a temporary Go test for each CRITICAL.

## 1. CRITICAL and HIGH rows

| Finding | Verdict | Evidence | Corrected severity |
|---|---|---|---|
| OWASP-A04-001 (ACME issues any names) | **CONFIRMED** | `internal/acme/server.go:350-365`: newOrder never checks `ident.Type`. `server.go:626-640`: finalize passes only `dns` identifiers as `DNSNames` and never sets `CallerNamesOnly` or `Subject`. `internal/ca/engine.go:708-716`: CSR SANs are used when the caller supplies none, and IP/URI SANs always come from the CSR. `checkIssuancePolicy` (engine.go:83) is nil-safe and has no default rule. "Default config" holds where it counts: ACME is mounted only when `APP_CERTIFICATE_PROVIDER=ca` (`cmd/kryptkeeper/main.go:86,550`; `protocolMux` is passed to `bootstrap.RunWithProtocols` on the main `listenAddr` at `main.go:862`, published as 8080 in compose, with only a rate limiter in front), which is the docker-compose default (`docker-compose.yml:22`). EAB is off unless `APP_ACME_EAB_REQUIRED` is set. The attacker also needs an HTTP server the hub can reach, which the report implies but does not say. | CRITICAL (keep) |
| A01-001 (cross-tenant API-key mint) | **CONFIRMED** | `internal/bootstrap/handlers_auth.go:317-335` passes `req.Tenant` straight to `CreateAPIKey` (`auth_identity.go:239-277`), which does no tenant check. The GET filter (`handlers_auth.go:258-260`) and DELETE (`:383-397`) check only `isAdminRole`. The write gate (`authz_write_gate.go:121`) checks the `permAdmin` permission only, never the tenant. | CRITICAL under MT (keep) |
| A2A7-001 (backup and escrow bypass dual control) | **CONFIRMED** | `handlers_backup.go:36-85` and `handlers_key_escrow.go:42-80` check only `isAdminRole`. Neither calls `dualControl`. Only `/keys/{id}/export` does (`handlers_keys.go:298-316`). The caller chooses the backup and custodian passphrases, so the caller can decrypt the result. Default off: `key_dual_control.go:58-61`. | HIGH (keep) |
| A07-4 (self-approval via a minted principal_id) | **CONFIRMED** | `handlers_pending_actions.go:164` compares `pd.ID == action.ProposedBy`. `CreateAPIKey` accepts any free-text `principal_id` with role `pki-admin`. `canApproveActions` accepts `pki-admin`. Note that the supplement pass (`OWASP_A02_A07_SUPPLEMENT:16`) rated this MEDIUM and the final report raised it to HIGH without saying so. HIGH is defensible because it breaks a CLAUDE.md non-negotiable. | HIGH (keep; note the upgrade) |
| A01S-3 (key store has no tenant scope) | **CONFIRMED, under-rated** | `handlers_keys.go:149-160` checks `isAdminRole` only. Export at `:273-335` has no tenant predicate anywhere, and the key list (A01-006) shows the IDs. A tenant admin directly exfiltrates another tenant's **root CA private key**. That is at least as severe as A01-001, which is CRITICAL. | **CRITICAL under MT** |
| A01-002 (approved actions hit other tenants) | **CONFIRMED** | `pending_action_exec.go:37-130`: revoke, bulk_revoke and issue call `certProvider` with no tenant check. Propose (`handlers_pending_actions.go:72-79`) does not validate targets. No tenant-from-context scoping exists in the package. | HIGH under MT (keep) |
| A01S-4 (SSH CA: any principals) | **CONFIRMED** | `handlers_ssh_certs.go:211-262`: POST passes `req.Principals` unchecked to `sshkeys.IssueCert`, which enforces only non-empty principals and the TTL ceiling (`internal/sshkeys/ca.go:84-109`). The gate needs only `certificate.issue` (`authz_write_gate.go:76`), which `service-account` and `pki-operator` hold (`authz_custom_roles.go:307-316`). jwt/oidc bearer tokens are always `service-account` (`auth.go:308-327`). | HIGH (keep) |
| A02-4 (OIDC empty aud/iss) | **CONFIRMED (conditional)** | `auth_jwks.go:75-86` and `auth_hs256.go:66-78` skip the issuer and audience checks when those values are empty. `auth_config.go:120-121` reads them with no startup failure. No `nbf` check. This needs AUTH_MODE=oidc **and** an operator who omits the audience. The supplement rated it MEDIUM; the final report raised it to HIGH (the coordinator rates it HIGH for a public IdP). | HIGH only for OIDC with a public IdP; otherwise MEDIUM |
| TM-08 (user.manage is admin-equivalent) | **CONFIRMED** | `handlers_users.go:102-112`: PATCH sets any role with no "grant only what you hold" check. `user_db_provider.go:105` stores the role string unvalidated. `roleMayManageRoles` (`authz_custom_roles_handlers.go:57-67`) lets any user.manage holder PUT roles. No built-in role except pki-admin holds user.manage, so this needs a custom role. | HIGH (keep; precondition correctly stated) |
| OWASP-A10-001 (ACME http-01 SSRF) | **OVERSTATED** | `server.go:1190-1224` is real: unauthenticated, any host:port, default client follows redirects. But it is **blind** and GET-only. The response body goes only to the server log (`:1220`), and the challenge object records valid/invalid with no error detail. Requests are rate-limited to 30/min per IP (`main.go:512`). The report's own §4 rules out the metadata pivot (IMDSv2). | **MEDIUM** |
| LLM-001 / A01-004 (/audit is authn-only) | **OVERSTATED** | `handlers_audit.go:17-45` does authentication only (confirmed). But `session_id` is the client-supplied `X-Session-Id` header (`audit_events.go:44`), not a credential. In single-tenant (default) mode this is metadata disclosure to already-authenticated users. The cross-tenant part matches the other MT read leaks that the report groups as MEDIUM. §5 FG-6b itself lists A01-004 as MED, which contradicts §3. | **MEDIUM** (HIGH only if audit data held secrets) |
| IAC-001 (Terraform plain HTTP) | **CONFIRMED, wording overstated** | `user_data.sh.tpl:125` sets no TLS env; `compute/main.tf:141` sets a public IP. But ingress is limited to the operator CIDRs, which are required with no default (`networking/main.tf:107-115`, `variables.tf:36-47`). "On a public Elastic IP" omits that. Exploitation needs an on-path attacker. The module also never enables CA mode, so it is a reference deploy that does not fully work. | HIGH is borderline; state the SG restriction (MEDIUM-HIGH) |
| DEP-001 (provider grpc v1.79.2) | **OVERSTATED** (advisory IDs **CANNOT VERIFY**: govulncheck is not installed here, and the provider scan is not in `docs/security/*.txt`) | `terraform-provider-kryptkeeper/go.mod:24,28` confirm grpc v1.79.2 and x/net v0.48.0 (indirect). The source finding's own preconditions (`DEPENDENCY_FINDINGS:40-41`) say: local foothold only, the go-plugin handshake plus auto-mTLS, no per-method interceptors (so the authz bypass yields nothing), and the impact is a crash of the local provider process. | **MEDIUM** (local DoS of a CLI plugin) |

**Tally (13 rows):** 10 CONFIRMED (A01S-3 under-rated; IAC-001 with overstated wording), 3 OVERSTATED (A10-001, LLM-001/A01-004, DEP-001), 0 WRONG. DEP-001 advisory details CANNOT VERIFY. The A10-001 downgrade also matches the report's own MEDIUM for A10-002, the ACME connector port-scan oracle.

## 2. MEDIUM rows that are really higher

- **A01-006, write half (MT):** a tenant `pki-admin` can PUT the **global** `/api/v1/config/**`. `handlers_config.go:86,121` check `isAdminRole` only. The config includes `sso.oidc_jwks_json`, `sso.oidc_issuer` and `sso.oidc_audience` (`config_store.go`). In oidc mode, a tenant admin can swap in their own JWKS and mint bearer tokens with any tenant claim. They can also rewrite `/credentials/**` and `/delivery-plugins/**` globally. This is a cross-tenant **write** and should be **HIGH under MT**, not part of the "admin resources unscoped" MEDIUM group.
- **A2A7-006 (OIDC links by unverified email):** confirmed. `auth_oidc_login.go:545-555` falls back to `findUserByEmail`, and the file never mentions `email_verified`. With an IdP that allows a mutable or unverified email (the nOAuth class), an IdP user takes over a pki-admin account. Chain 07 is already CRITICAL. The finding should be **HIGH when OIDC login is enabled**.
- The other MEDIUMs I sampled are rated correctly: LLM-004 (the MCP HTTP transport is opt-in and binds to loopback by default, `cmd/kryptkeeper-mcp/main.go:17-25`), A01-003 and SEMGREP-012/013.

## 3. Verdict (§1) and fix order (§5)

- The §1 verdict ("not ready for a public release") is correct and well supported.
- **Count inconsistency:** §1 says "about 10 HIGH"; §3 says "HIGH 11".
- **Severity inconsistency:** A01-004 is HIGH in §3 but MED in FG-6b. FG-13 is marked HIGH only because of DEP-001, which is overstated.
- **Undisclosed upgrades:** A07-4 and A02-4 are MEDIUM in the supplement but HIGH in the final report, with no note.
- **Missing precondition in §1 item 1:** the attacker also needs an HTTP endpoint the hub can reach, and the ACME surface exists only in `APP_CERTIFICATE_PROVIDER=ca` mode (the compose default).
- **FG-1 scope is right and needed:** my test shows that even a valid `dns` order lets the CSR add IP SANs, URI (SPIFFE) SANs and the Subject. Restricting identifiers to `dns` alone would not fix this; `CallerNamesOnly` plus an order-derived Subject must ship together, which FG-1 already lists.
- **FG ordering is sound:** FG-1 is the only unauthenticated default-config CRITICAL. FG-6a is gated on the MT decision, which is reasonable. FG-6a should also take the A01-006 config/credentials **writes**: they are currently in its "Closes" column, but they need HIGH priority if MT ships.

## 4. Test results

**Test 1, OWASP-A04-001** (`internal/acme/zz_challenge_tmp_test.go`, now deleted). This is a full unauthenticated ACME flow against the in-repo server. The account has no EAB. The http-01 challenge is served on the attacker's own loopback host. The CSR carries `CN=www.victim-bank.example, O=Victim Bank`, DNS `www.victim-bank.example` and `*.victim-bank.example`, IP `10.9.9.9`, and URI `spiffe://victim.example/ns/prod/sa/admin`.

| Order identifier type | Issued certificate |
|---|---|
| `ip` | CN and O from the CSR; DNS = **both victim names, including the wildcard**; IP 10.9.9.9; the SPIFFE URI |
| `bogus` (an unknown type is accepted) | same as `ip` |
| `dns` (the attacker's own host) | DNS = the order host only, but **IP, the SPIFFE URI and CN/O still come from the CSR** |

Result: **CONFIRMED.** It is in fact broader than the report says. An unknown identifier type works too, and a correct `dns` order still leaks IP SANs, URI SANs and the Subject.

**Test 2, A01-001** (`internal/bootstrap/zz_challenge_tmp_test.go`, now deleted). It uses the existing `setupTenantWritePathTest` setup: MULTI_TENANCY on, tenants acme and globex.

- Baseline: the acme admin's GET of `/cas/ca-globex` returns **403**.
- The acme admin POSTs `/api-keys` with `{"tenant":"globex","role":"pki-admin"}` and gets **201**, with a key bound to globex.
- The minted key's GET of `/cas/ca-globex` returns **200**.
- The acme admin's GET of `/api-keys` lists globex's key.
- The acme admin DELETEs globex's key and gets **204**. Globex's own token then gets **401**.

Result: **CONFIRMED**, including the list and delete halves and a denial of service against the other tenant.

## 5. Score

**8 / 10** for accuracy. Both CRITICALs reproduce (the ACME one is broader than reported), and no finding is wrong. Points come off for:

- three HIGHs that should be MEDIUM: A10-001, A01-004/LLM-001 and DEP-001;
- one under-rated HIGH (A01S-3) and two under-rated MEDIUMs (the A01-006 config writes and A2A7-006);
- the internal inconsistencies: the HIGH count, A01-004 HIGH vs MED, and the undisclosed severity upgrades.
