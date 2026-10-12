# Manual review findings (RC `d74edf3` vs `6d81d72`)

Class: NEW / INCOMPLETE-FIX (of an FG) / RESIDUAL (previously known). Confidence in brackets. Found by three read-only
reviews (A renewal/egress, B authn/authz, C protocols/keys/UI) and own live probes (M, U).

## HIGH
**RC1-A-01 HIGH NEW [85] - discovery role can make the scheduler push any hub certificate+key to a credential's target.**
`internal/bootstrap/renewal_scheduler.go:621-633` (autoRenewSkipReason now accepts f5/citrix/k8s/iis with only a
`credential_ref`), `:643-653` (matchAutoRenewTarget: CN/SAN string match only), `handlers_targets.go:172,308`,
`authz_write_gate.go:101` (`/api/v1/targets/** -> discovery.manage`). Create does not check the credential exists, its type
or tenant (live: 201 with `cred-doesnotexist`). `GET /targets` exposes other targets' `credential_ref`. The scheduler lists
all certs and targets with no team/tenant filter and renews as `renewal-scheduler`, skipping `authorizeCertificateResourceAccess`.
Exploit: discovery-operator creates `{host:"payments.example.com", install_mode:"k8s", credential_ref:<dev cluster cred>,
auto_renew:true, renewal_threshold_days:3650}`; next tick the hub renews the payments cert and writes cert+key into the dev
cluster Secret (readable ~135 s per attempt, up to 5 retries; permanent if verify_host_port points at an ingress serving it).
Fix: arming auto_renew / setting credential_ref / install_* requires `certificate.renew` on the matched cert (and tenant/team
match) or pki-admin approval; validate credential exists, matches install_mode and tenant at create/PATCH; scheduler re-checks
target creator vs cert ownership; add target_id to every scheduler audit row.

## MEDIUM
- **A-02 NEW [80]** `renewal_threshold_days` unbounded (`managed_target_store.go:191-196`); with threshold >= 90 (hardcoded validity,
  `certificate_ca_provider.go:550`) every tick renews+reloads forever. Fix: cap below validity/2, cooldown after success.
- **A-03 NEW [80]** `/renewal/execute` takes the install profile from the request body (`handlers_renewal_execute.go:128`): caller-chosen
  cert/key paths, server_type (used as systemd unit in `agentinstall/installer.go:279-295`), verify_host_port; reachable by
  service-account/pki-operator with certificate.renew. Impact: write PEM to arbitrary paths / reload arbitrary units as the credential
  user via SSH. Fix: use target's stored profile; override only for pki-admin; enum + path allowlist.
- **A-04 NEW [85]** verify-after-install TLS dial not egress-guarded (`agentinstall/verify.go:34-38`, `renewal_executor.go:288,735`):
  verify_host_port 169.254.169.254/loopback accepted (live: create 201) and dialed; error text lands in API response and audit.
  Fix: `Control: egress.Policy{AllowPrivate:true}.DialControl()`, generic errors.
- **B-01 INCOMPLETE FG-2 [85]** `separation_of_duties.go:26-35,92-99`: key minted with the bootstrap token has canonical human `bootstrap`;
  only AuthType==bootstrap is refused as approver, so one person (SSO admin + bootstrap token) proposes with one, approves with a
  bootstrap-minted key and redeems key export/backup. Fix: refuse approver/redeemer whose canonical human is `bootstrap`; recommend
  `KRYPTKEEPER_DISABLE_BOOTSTRAP_TOKEN=true` when dual control is relied on.
- **B-02 INCOMPLETE FG-2 [80]** `key_dual_control.go:183-188,225`: grant bound to proposer's free-text principal id; a third admin mints an
  API key with `principal_id:"alice"` and redeems alice's approved grant within 10 min. Fix: bind to canonical human + credential
  (AuthType, Kid); refuse API-key principal_id equal to an existing user/login subject.
- **B-03 NEW [85]** `spiffe_workload.go:298` unauthenticated `json.NewDecoder(r.Body).Decode` with no cap on `/api/v1/spiffe/workload-svid`
  (SPIFFE configured): memory DoS. Fix: `decodeJSONBodyOrReject(... maxAuthBodyBytes ...)`. Other authenticated routes also uncapped
  (users invite/PATCH, custom roles x3, tenants x3, nhi propose, pqc-waves, evidence, notifications x2, pending-action reject reason) = LOW.
- **C-01 INCOMPLETE SUP-A04-3 [80]** `internal/ca/name_policy.go:142` (default `CNMustBeSAN=false`): CN-only CSR with no SANs bypasses
  `allowed_dns_suffixes` (engine.go:722, renewal certificate_ca_provider.go:589); CMP path does check CN. Tests all use CNMustBeSAN:true.
  Fix: always `dnsAllowed(cn)` when DNS restrictions exist.
- **M-1 NEW [80] (own)** Login limiter is per-IP (+per-account backoff). Shipped `nginx.conf`, `docker-compose.yml`, charts do not set
  `APP_TRUSTED_PROXY_CIDRS` (only commented in env.example), so everything behind nginx shares the nginx IP bucket: ~9 bad logins/min
  from anyone locks all UI users out of login (live: correct password gets 429 while limited), and audit `source_ip` is the proxy.
  Fix: set the CIDR in compose/helm defaults (proxy network) and forward X-Forwarded-For consistently; document.
- **M-2 RESIDUAL-to-RELEASE [90] (own)** RC `dist/` binaries built with go1.27.1 carry 11 reachable stdlib CVEs (fixed 1.27.2). See 01-automated.md.

## LOW (new)
A-05 HA lease `2*pollInterval` shorter than a 10-min scan; second replica can double-renew [70]. A-07 f5/citrix/k8s pushers use
`http.DefaultClient` without timeout. A-08 `elevationReason` deny-list bypassable (find -exec sudo, systemd-run); mitigated for plugins.
A-09 discovery scanner deny-list checks literal IPs only (DNS rebinding). B-04 TCP syslog writes lack deadlines: stalled collector wedges the
single SIEM drain worker and the `/integrations/siem/test` mutex [80]. B-05 SIEM test endpoint can echo the webhook URL via `url.Error` [70].
B-07 pending-SAML-request table (4096) can be filled by 4 IPs to block SSO [75]. B-08 `targetUserRefusal` and custom-role PUT/DELETE
pre-check fail open on store errors [70]. C-02 `Content-Disposition` filename built from CSR CN unescaped (`handlers_certificates.go:744`) [85].
C-05 ACME http-01 client hardcodes `AllowPrivate:true`, ignores `KRYPTKEEPER_EGRESS_DENY_PRIVATE`, follows redirects to RFC1918:80/443 (blind
SSRF GET, 30/min/IP; loopback/metadata blocked) [75]. C-06 MCP error results skip the untrusted-output wrapper [70].
U-1 (own, live) `GET /api/v1/users` returns the whole user directory (email, role, status) to any authenticated principal incl. viewer and
mcp-agent (`handlers_users.go:31-65`; no read permission) [85]; fix: require `user.manage` or `audit.read`.

## LOW (residual / incomplete earlier fix)
A-06 successor check under RLock then link under Lock: concurrent runs mint two successors. B-06 SAML login CSRF (no browser-binding
cookie, unlike OIDC) [80]. C-03 key-strength floor only in ACME/CMP, not engine/EST/SCEP/template-less issuance (A04-002) [85].
C-04=B-09 `/inventory/keys` readable by viewer (report.read) and JWT/OIDC default role viewer; uncached live cloud fan-out; ARNs in
`key_id` (CLOUD-001 residual) [80]. I-1 OCSP signs "good" when revocation store is nil (`cmd/kryptkeeper/main.go` ~555); I-2 OCSP cache
race between status lookup and insert. M-3 nginx static dashboard sends only `frame-ancestors 'none'` CSP, no script-src/HSTS (OWASP-003 residual).

## INFO
IPv6 /64 not aggregated in limiters; Ratelimit buckets never swept; trusted-proxy hosts can spoof XFF (inherent); `canApproveActions` hardcodes
roles; SCIM can set any role (TM-19); egress `checkIP` misses ::/96 and 2002::/16; startup_ca first-boot two-replica race; BYOK raw KMS errors
(admin+dual control); dual-control `redeemed` set is per process/replica; template PUT clears omitted name/ssh policy; SIEM forwards 7 action
types only; `AuthorizeExport` dead code; scheduler failure audit lacks target id; credentials tenant "" (FG-6a deferred); login account lockout
is an admin-lockout DoS by design (A07-8 comment) and lockout answers faster than a KDF compare (timing hint only for locked accounts).

## FG spot-check of earlier top findings
| Finding | Status |
|---|---|
| A04-001 ACME any-name issuance (CRIT) | HOLDS: dns-only identifiers, CSR==order, CallerNamesOnly, http-01 port 80; 349 acme/cmp/ca/ocsp tests ok |
| A2A7-001 key egress past dual control | HOLDS (live 202 proposed; all 7 routes gated) but B-01/B-02 weaken separation |
| A07-4 proposer != approver | HOLDS by canonical human, with B-01/B-02 identity gaps |
| TM-08 / FG-3 grant-only-what-you-hold | HOLDS (invite, PATCH, roles, API keys; live api-key escalation 403) |
| A02-4 / FG-5 OIDC aud/iss, HS256>=32B, bootstrap compare | HOLDS (code + tests) |
| A2A7-002..008 / FG-7 Argon2id, logout revoke, SAML replay, redirect | HOLDS (B-06 residual) |
| FG-9 issuance policy | HOLDS except C-01 default-flag gap |
| FG-10 MCP, FG-8 egress | HOLDS (C-05/A-04 are additional dial paths) |

## Checked and held (summary)
Write gate vs low roles and path tricks; credentials admin-only; ACME/CMP/OCSP/EST protections; SSH principal policy default-deny; Argon2id
params/constant-time; clientip right-to-left walk; request-body caps on login/refresh/api-keys/SCIM; SIEM non-blocking and masked; no key
bytes in logs/errors/audit; cert download never includes keys, `include_chain` excludes root; startup CA no secret logging.
