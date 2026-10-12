# OWASP A03 / A04 / A08 / A10 findings, 2026-10-09 (kryptkeeper, --deep, focused slice)

Category: owasp-web. Agent: owasp-web-checker. A01, A02 and A07 are out of scope because other agents cover them.
Cross-referenced against SEMGREP_FINDINGS, OWASP_WEB_FINDINGS, LLM_FINDINGS and CLOUD_FINDINGS (all 2026-10-09). None of the findings below repeats an existing ID.
Proof method: temporary Go tests in `internal/acme/zz_audit_tmp_test.go` and `internal/discovery/scanner/zz_audit_tmp_test.go`. Both files were deleted after running. No product code was changed.

## Confidence

| Category | Confidence | Status |
|---|---|---|
| A03 Injection | 7 | DONE |
| A04 Insecure Design (protocol and issuance policy) | 7 | DONE |
| A08 Software and Data Integrity (delivery plugins) | 7 | DONE |
| A10 SSRF | 6 | NEEDS_REVIEW (commercial CA adapters, CT monitor, OIDC JWKS and SAML metadata were not traced) |

## REAL findings

### OWASP-A04-001 (CRITICAL): ACME finalize does not bind the CSR's names to the validated identifiers. An unauthenticated client gets certificates for any name.
- file: internal/acme/server.go:625-640 (only `type=="dns"` identifiers are copied into `DNSNames`; `CallerNamesOnly` is not set); internal/ca/engine.go:704-715 (CSR DNS, IP and URI names are used whenever the caller's list is empty); internal/acme/server.go:350-365 (new-order validates neither identifier type nor value); internal/acme/eab.go:156 (EAB is off unless `APP_ACME_EAB_REQUIRED=true`); cmd/kryptkeeper/main.go:535-550 (ACME is mounted on the protocol mux).
- proof (test, PASS):
  - An order with identifier `{type:"ip", value:<attacker host:port>}` was validated over http-01 against the attacker's own server and then finalized with any CSR. The issued cert was `CN=bank.example.com DNS=[bank.example.com *.corp.example] IP=[10.0.0.1] URI=[spiffe://prod.example/ns/admin]`.
  - With a `dns` identifier, the CSR can still add any IP SAN, URI SAN and CN.
- impact: Anyone who can reach /acme/ gets serverAuth certificates from the default CA for any DNS name, wildcard, IP or SPIFFE URI. Every relying party that trusts that CA can then be MITM'd.
- fix:
  - Reject identifiers whose type is not dns, and validate the value as a hostname (no port, path or userinfo).
  - Set `CallerNamesOnly: true` and `Subject` from the identifiers.
  - Refuse a CSR whose SAN set is not exactly the order's identifiers (RFC 8555 §7.4).
  - Make EAB the default.

### OWASP-A10-001 (HIGH): ACME http-01 validation is an unauthenticated SSRF that follows redirects
- file: internal/acme/server.go:1191-1193 (`fmt.Sprintf("http://%s/...", identifier)` with a default `http.Client` that follows redirects); :1222 (logs the first 512 bytes of the response body).
- proof (test, PASS): The identifier was a host:port that returns a 302 to an internal URL. The internal server received `GET /latest/meta-data/iam/security-credentials/?x=1`. Loopback and any port were accepted as identifiers; the existing suite already relies on `127.0.0.1:<port>` being accepted.
- impact: No authentication is needed (EAB is off by default). The hub sends GET requests to any internal, loopback or 169.254.169.254 URL on any port or path. The status code is visible through the authz state, and part of the response body is written to the hub log.
- fix:
  - Validate identifiers as described under A04-001.
  - Dial port 80 only.
  - Refuse private, loopback and link-local destinations through a dialer guard, re-checked on every redirect.
  - Limit redirects to http/https on ports 80 and 443.
  - Do not log response bodies.
- note: this sink is different from SEMGREP-001/002.

### OWASP-A08-001 (MEDIUM): The plugin `elevated_exec` capability is only checked against the basename of argv[0]
- file: internal/plugins/delivery/host.go:334-336
- proof (read): The only refusal is for `path.Base(argv[0])` being `sudo` or `doas`. Inputs such as `["sh","-c","sudo …"]`, `["env","sudo",…]`, `su`, `pkexec` and `busybox sudo` all pass. The SSH executor quotes each argument and runs them verbatim (internal/agentinstall/executor_ssh.go:265-275), so the command inside runs as written.
- impact: An approver who grants `remote_exec` without `elevated_exec` believes the plugin cannot get root. If the deploy account has NOPASSWD sudo, the plugin gets root anyway.
- fix: Run non-elevated execution under an account with no sudo rights, or apply an argv allowlist. Do not rely on matching argv[0].

### OWASP-A04-002 (MEDIUM): No key-strength floor on ACME or CMP issuance unless policy rows exist
- file: internal/ca/engine.go:453-480 (the only key checks are CSR signature verification and `checkIssuancePolicy`, which returns nil when no policy is configured). internal/acme/server.go:633 and internal/cmp/server.go:130 pass no `Policy`.
- proof (test, PASS): ACME issued a leaf for an RSA-1024 CSR key. Read: `PolicyEngine.Check` (internal/ca/policy_engine.go:232-233) returns nil when no policy rows exist, and enforces `min_rsa_bits` only when a row sets it. Production therefore has no built-in floor either.
- fix: Enforce a hard floor in the engine (RSA ≥ 2048, approved curves) regardless of the policy table.

### OWASP-A10-002 (MEDIUM): The ACME upstream connector health probe fetches directory_url with no egress guard and returns raw dial errors
- file: internal/bootstrap/connector_acme.go:96-103; the result is surfaced by GET /api/v1/connectors at internal/bootstrap/handlers_connectors.go:93.
- proof (read): `directory_url` comes from connector config, which `discovery.manage` can write (authz_write_gate.go:102). It is fetched with a plain client, and `err.Error()` (refused, timeout, or `directory returned N`) is returned as `Health.Detail`.
- impact: An authenticated user can make the hub probe internal hosts, and the error text reveals whether each port is open.
- fix: Same egress guard as SEMGREP-001, and return a generic error detail.

### LOW
- **OWASP-A10-003**: The discovery scanner has no deny-list for loopback, link-local or metadata addresses. The test accepted `169.254.169.254/32` and `127.0.0.1/32`, and no filter exists in handlers_discovery.go or discovery_scanner_provider.go. The scanner returns TLS certificate data and a Server-header classification (scanner.go:300-318), not response bodies. It can only be reached with `discovery.manage`, and scanning internal ranges is the feature's purpose, so this is LOW.
- **OWASP-A04-003**: The CMP PBM `iterationCount` can be up to 1,000,000, and it is hashed before the MAC is checked (internal/cmp/protection.go:79-89). This is unauthenticated CPU amplification, limited to 30 requests/min per IP. Cap it around 10k. (read)
- **OWASP-A04-004**: The ACME nonce map is cleared entirely once it holds 10,000 nonces (internal/acme/nonce.go:43-45). Any client can flood it and invalidate every outstanding nonce. Evict oldest-first instead. (read)
- **OWASP-A04-005**: Discovery CIDR expansion has no size cap (internal/discovery/scanner/scanner.go:432-447). The test expanded `/12` to 2,097,156 targets. `0.0.0.0/0` would exhaust hub memory. Only the scanner layer was tested; the API handler (handlers_discovery.go, which caps ports but not CIDR size) was not traced end to end.
- **OWASP-A03-001** (UNVERIFIED runtime): The WinRM `cmdQuote` only quotes whitespace and `"` (internal/agentdiscovery/agentless_winrm.go:398-402). If IIS `ipport`, `app_id` or `store_name` from the push credential (renewal_executor.go:541-544) contain cmd metacharacters (`&|^<>`), they reach `netsh`/`certutil` (internal/agentinstall/iis.go:245,355,460) unescaped. Exploiting this needs credential write access. Validate `IPPort` as `ip:port` and `AppID` as a GUID.

## Existing findings confirmed (not re-raised)
- SEMGREP-012 is confirmed by reading:
  - An unknown IssuerKeyHash falls back to the default CA (cmd/kryptkeeper/main.go:1071-1086).
  - A serial that is not revoked is signed `Good` (main.go:555-571).
  - The cache is keyed by serial only, with a flush-all at 10,000 entries (internal/ocsp/responder.go:130-181).
- SEMGREP-013 is confirmed by the same read.

## Checked, no finding
- **ACME JWS** (internal/acme/jws.go:90-150): checks the alg allowlist (RS256/ES256/EdDSA), exact url match, single-use nonce, mutual exclusion of jwk and kid, and an RSA account-key floor of 2048.
- **ACME account binding**: account ownership is checked on challenges and finalize. The http-01 and dns-01 key authorizations are bound to the account thumbprint.
- **Other enrollment protocols**: EST, SCEP and WSTEP take names from the authenticated identity with `CallerNamesOnly`. The SCEP challenge is consumed atomically with a single UPDATE. The CMP PBM gate runs before any processing.
- **CSR extensions** are never copied. `ExtraExtensions` come only from the caller, and engine-controlled OIDs are refused.
- **XML parsing**: WSTEP and XCEP use `encoding/xml`, so XXE is not possible.
- **Delivery plugins**:
  - The wasm sha256 is pinned to the manifest, and approval is bound to that sha256.
  - Signature tiers use ECDSA P-256 over the manifest.
  - `http.do` allows https only, checks host and port grants (including on redirects), and refuses userinfo.
  - `file_write` blocks `..` and enforces the granted prefix.
- **Command, query and filter construction**:
  - SSH executor arguments are single-quoted.
  - WinRM PowerShell uses `-EncodedCommand` with psQuote.
  - SQL uses placeholders throughout, and `orderDir` is a constant.
  - The adsync LDAP filter is a constant.
  - No `html/template` or `text/template` rendering of user data was found.

## Not covered
CRL generation, XCEP template policy (W20-09/17) in depth, bulk reissue and imported-certificate trust, commercial CA adapters, CT monitor, and dns-01 lookups of arbitrary names. OIDC issuer/discovery and SAML IdP URLs are set only through operator env vars (internal/bootstrap/auth_config.go:120-173), so users cannot reach them and they are not an SSRF.

# Completion Manifest

## Files produced
- `docs/security/OWASP_A03_A08_A10_FINDINGS_2026-10-09.md`: A03/A04/A08/A10 findings with confidence scores.

## Files modified
- None. The two temp test files were created and then deleted, and no product code was touched.

## Decisions made
- A01, A02 and A07 were skipped as the HANDOFF directed.
- Findings were proven with temporary Go tests run against the in-package ACME test server and the scanner.
- OWASP_TRACKER.md was not edited, because the write-scope covers this one file only.

## Known issues / deferred
- See "Not covered". A10 is held at 6 until the commercial CA adapters and CT monitor are traced.

## Verify result
- PASS: the ACME name-binding, redirect-SSRF and RSA-1024 tests and the scanner CIDR test all ran and passed (`go test ./internal/acme -run TestAudit`: ok). Evidence: `docs/security/OWASP_A03_A08_A10_FINDINGS_2026-10-09.md`.

## Memory written
- None.
## Model tier: large (medium context)

Maker: owasp-web-checker
Verifier: advisor review (separate model)

## Ready for: attack-chainer

owasp-a03-a08-a10 done
