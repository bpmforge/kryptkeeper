# SEMGREP_FINDINGS 2026-10-09 (kryptkeeper, --deep audit, SAST phase)

## Coverage statement (read first)

- **SAST engine: RUN (second pass, same day).** Opengrep v1.30.2 (`~/.local/bin/opengrep`, signature verified) with in-house bpm-rulepacks only (`packs/owasp`, `packs/secrets`, `packs/slop`, `packs/framework`, `packs/house`). No registry, community or `--config auto` rules were used. See "Engine run (opengrep + bpm-rulepacks)" below.
- **First pass (no engine) still stands:** `govulncheck v1.8.0` on the root module (`docs/security/govulncheck_.txt`), `npm audit` on `ui/` (`docs/security/npm-audit.json`), and targeted grep sweeps + manual reading of `internal/`, `cmd/`, `sdk/`, `plugins/`, `ui/src`. Findings SEMGREP-001..011, DEP-001..002 come from that pass.
- **Gaps:**
  - `govulncheck` on `sdk/` and `plugins/` returned "no packages matched" (nested modules / build tags), so those modules have no CVE coverage.
  - `ast-grep` is not installed, so the `bpm-rulepacks/astgrep/` rules did not run.
  - `scripts/semgrep-full-audit.sh` does not exist in this repo; the engine was invoked directly with an explicit pack list, per the HANDOFF.
  - Rulepack gap: `bpm-owasp-a02-tls-verify-disabled-go` matches only the literal `InsecureSkipVerify: true`. `internal/certmanager/connector.go:152` (`InsecureSkipVerify: cfg.SkipVerify`, SEMGREP-003) was invisible to the engine; it is covered by the manual pass only.
  - Tenancy scoping through the stores is not covered here (handed to owasp-web-checker A01).
- `category: semgrep` covers the code findings, even where `tool: manual`. `category: dependency` covers the CVE findings.

## Summary

| Status | Count |
|---|---|
| REAL | 8 (CRITICAL 0, HIGH 0, MEDIUM 5, LOW 3). 2 new from the engine pass: SEMGREP-012 (MEDIUM), SEMGREP-013 (LOW) |
| UNVERIFIED | 8 (SEMGREP-005..011, SEMGREP-014) |
| FP | 11 groups (first pass) + 5 groups (engine security rules) |
| Code-health (slop) | 275 engine results, bucketed in "Code-health (slop) results" |

---|---|
| REAL | 6 (CRITICAL 0, HIGH 0, MEDIUM 4, LOW 2) |
| UNVERIFIED | 7 |
| FP | 11 groups |

---

## REAL findings

### SEMGREP-001: Unvalidated webhook destination in notification delivery (authenticated SSRF)
- severity: MEDIUM | category: semgrep | tool: manual (grep sweep)
- file: internal/notifications/delivery/delivery.go:302
- evidence:
  ```go
  req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
  ...
  resp, err := httpClient.Do(req)
  ```
  - Line 23 uses `var httpClient = &http.Client{Timeout: 10 * time.Second}`. It has no `CheckRedirect` and no dialer `Control` hook.
  - No private, loopback or link-local IP check exists anywhere in `internal/notifications` or `internal/bootstrap/*notif*`.
  - Operator-supplied `c.Headers` are set on the request.
- preconditions:
  - "authenticated with notification.manage". This covers pki-operator, notification-operator, and API keys scoped `*`, `ops:write` or `notifications:write` (authz_write_gate.go scopePermissions).
  - "can send HTTP requests to /api/v1/notifications/**"
- yields:
  - "hub-originated POST to arbitrary internal host:port with attacker-chosen headers"
  - "internal network port/host probing via delivery success/failure"
  - "event payloads (cert metadata) exfiltrated to attacker URL"
- asset: hub network position (cloud metadata, internal admin APIs)
- status: REAL
- remediation: Validate webhook URLs at save time and again at dial time. Use a `net.Dialer.Control` that rejects loopback, private, link-local and metadata IPs. Disable or re-check redirects, and require https.

### SEMGREP-002: Unvalidated inventory-source base URL (authenticated SSRF with response ingestion)
- severity: MEDIUM | category: semgrep | tool: manual
- file: internal/bootstrap/inventory_source.go:187 (also inventory_source_commercial.go:82,163,354)
- evidence:
  ```go
  req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.baseURL+path, nil)
  ```
  - `baseURL: strings.TrimRight(cfg.BaseURL, "/")` comes from the config with no host validation.
  - The client is `&http.Client{Timeout: 30 * time.Second}`, with no dial guard.
- preconditions: "authenticated with discovery.manage (discovery-operator, pki-operator, API key ops:write/discovery:write)"
- yields:
  - "hub-originated GET to arbitrary internal URL"
  - "response content parsed into inventory; read-SSRF if the parsed fields are later shown in the UI (UNVERIFIED)"
  - "stored credential_ref sent as auth header to attacker-chosen host"
- asset: inventory-source credentials and the internal network
- status: REAL. The missing validation is confirmed. How much of the response is reflected is unverified.
- remediation: Apply the same egress guard as SEMGREP-001. Bind credentials to the host that was approved when the source was created.

### SEMGREP-003: cert-manager connector can disable TLS verification globally while sending a bearer token
- severity: MEDIUM | category: semgrep | tool: manual
- file: internal/certmanager/connector.go:152 (env source at :76)
- evidence:
  ```go
  SkipVerify:   strings.EqualFold(os.Getenv("KRYPTKEEPER_K8S_SKIP_VERIFY"), "true"),
  ...
  tlsCfg := &tls.Config{InsecureSkipVerify: cfg.SkipVerify}
  ```
  - This is plain skip-verify. It is not the documented fingerprint verifier (agentinstall/verify.go).
  - The connector sends the `token` field (a k8s bearer) over this connection.
- preconditions:
  - "operator set KRYPTKEEPER_K8S_SKIP_VERIFY=true"
  - "network position between hub and k8s API (MITM)"
- yields:
  - "Kubernetes service-account bearer token"
  - "ability to forge cert-manager responses to hub"
- asset: k8s SA token, issued-certificate integrity
- status: REAL. The behaviour is gated by a config flag, but the flag contradicts the "never loosen verification" rule in CLAUDE.md.
- remediation: Replace with CA-pin or SPKI-fingerprint verification (`VerifyConnection`), and remove the env bypass.

### SEMGREP-004: Agent bearer token written to process log
- severity: LOW | category: semgrep | tool: manual
- file: cmd/kryptkeeper-agent/main.go:147
- evidence:
  ```go
  log.Printf("set KRYPTKEEPER_AGENT_ID=%s and KRYPTKEEPER_AGENT_TOKEN=%s to persist credentials",
      resp.AgentID, resp.Token)
  ```
- preconditions: "read access to agent host logs / journald / log shipper"
- yields: "agent bearer token (impersonate agent: heartbeat, inventory, renewal-result on /api/v1/agent/**)"
- asset: agent credential
- status: REAL. This violates the CLAUDE.md rule "no key bytes in logs".
- remediation: Write the token to a 0600 file, or print it once to stdout on a TTY only. Never send it through `log`.

### DEP-001: Go stdlib go1.27.1 has 11 reachable vulnerabilities (fixed in go1.27.2)
- severity: MEDIUM | category: dependency | tool: govulncheck
- file: go.mod (toolchain). Sample traces:
  - internal/mcpserver/transport_http.go:66
  - internal/bootstrap/auth_saml.go:188
  - internal/agentclient/client.go:231
- evidence:
  - GO-2026-6617, -6613, -6612, -6611, -6610, -6608, -6607, -6605 and 3 more. The full list is in docs/security/govulncheck_.txt.
  - The summary line reads "Your code is affected by 11 vulnerabilities from the Go standard library."
  - Reachable paths include the http2 server via `mcpserver.ServeHTTP`, and multipart `ReadForm` via the unauthenticated SAML ACS route `PostFormValue`.
- preconditions: "can send HTTP requests to hub (SAML ACS is pre-auth)"
- yields: "likely DoS of the hub process (per-advisory impact not individually verified)"
- asset: hub availability
- status: REAL. Reachability is confirmed by govulncheck.
- remediation: Bump the toolchain to go1.27.2 and rebuild all binaries.

### DEP-002: UI dev and build toolchain has known-vulnerable packages
- severity: LOW | category: dependency | tool: npm-audit
- file: ui/package-lock.json
- evidence:
  - Totals: 34 vulns (1 critical, 21 high, 10 moderate, 2 low).
  - Direct dependencies with advisories: vite 8.0.0-8.0.15, shadcn, react-router-dom. Fixes are available for all of them.
  - Most of the rest are build-time transitives: braces, micromatch, postcss, js-yaml, ts-morph, undici and similar.
- preconditions: "developer/CI machine runs the toolchain against attacker-influenced input"
- yields: "build-host DoS / limited dev-server exposure"
- asset: CI/dev hosts
- status: REAL as a dependency hygiene finding.
- remediation: Run `npm audit fix` and bump vite, shadcn and react-router-dom.

### SEMGREP-012: OCSP responder signs for unknown issuers and caches by serial only (unauthenticated OCSP cache poisoning)
- severity: MEDIUM | category: semgrep | tool: opengrep (`bpm-slop-fallback-hides-failure-go` at cmd/kryptkeeper/main.go:1059,1075) + manual trace
- file: cmd/kryptkeeper/main.go:1086; internal/ocsp/responder.go:130
- evidence:
  ```go
  // cmd/kryptkeeper/main.go:1078-1086 (ocspResolveIssuerByKeyHash)
  for _, c := range cas {
      ...
      if h := ocspPublicKeyHash(c.Certificate); bytes.Equal(h, keyHash) {
          return c, nil
      }
  }
  return engine.GetCA(defaultCAID)
  ```
  ```go
  // internal/ocsp/responder.go:130,141,147,177
  cacheKey := req.SerialNumber.String()
  issuerCert, signer, err := r.issuerFunc(req.IssuerKeyHash)
  revoked, revokedAt, reason, err := r.statusFunc(req.SerialNumber, issuerCert)
  r.cache[cacheKey] = cachedResponse{body: respBytes, expiresAt: now.Add(r.validity)}
  ```
- detail:
  - A request whose IssuerKeyHash matches no CA is not refused (RFC 6960 `unauthorized`). It falls back to the default CA, which looks the serial up in its own revocation store and signs a `good` response.
  - The response is cached for 24h (`24*time.Hour`) under the serial alone, not (issuer, serial). A later legitimate request for the same serial under a different CA gets the cached response, which is signed by the wrong CA and carries the wrong CertID.
  - Relying parties reject that response as unverifiable. Soft-fail clients (most browsers and TLS stacks) then accept the certificate, so a revoked certificate passes for up to 24h. Hard-fail clients cannot validate it at all (DoS of that cert).
  - `InvalidateCache(serial)` on revoke does not help: the attacker re-poisons after it.
- preconditions: "network reach to /ocsp (unauthenticated, rate-limited only); serial of target cert (public); target cert issued by a CA other than the default CA, or a bogus IssuerKeyHash"
- yields: "revoked certificate accepted by soft-fail relying parties for up to 24h; OCSP DoS for a chosen serial; signed 'good' responses for arbitrary serials from the default CA"
- asset: revocation integrity (PKI trust)
- status: REAL. Deterministic code path, no DB error needed. Not exercised against a running hub.
- remediation: Return `unauthorized` (or an error) when no CA matches the IssuerKeyHash; never fall back to the default CA. Key the cache by (IssuerKeyHash, IssuerNameHash, serial). Optionally answer `unknown` for serials the CA never issued.

### SEMGREP-013: OCSP status lookup fails open to the default CA when the CA list cannot be read
- severity: LOW | category: semgrep | tool: opengrep (`bpm-slop-fallback-hides-failure-go`, cmd/kryptkeeper/main.go:1059) + manual
- file: cmd/kryptkeeper/main.go:1057-1060, consumed at :560-561
- evidence:
  ```go
  cas, err := engine.ListCAs()
  if err != nil {
      return defaultCAID
  }
  ```
  ```go
  caID := ocspResolveCAID(caEngine, issuer, defaultCAID)
  revoked, at, reason, err := revStore.IsRevoked(serial, caID)
  ```
- detail: `IssuerLookupFunc` and `CertStatusFunc` each call `ListCAs()` separately. If the issuer lookup succeeds (CA B) and the status lookup's `ListCAs()` errors, the revocation check runs against the default CA's store. A cert revoked under CA B is signed `good` by CA B, and that response is cached for 24h (see SEMGREP-012). The comment in internal/acme/server.go:884-890 calls this fallback "harmless" for a read; it is not harmless for a revocation read.
- preconditions: "multi-CA deployment; transient DB/CA-store error between the two lookups"
- yields: "valid, correctly signed 'good' OCSP response for a revoked certificate, cached 24h"
- asset: revocation integrity
- status: REAL as a code defect (fail-open on error). Exploitability depends on inducing a DB error, so LOW.
- remediation: Return an error (→ OCSP `tryLater`) when `ListCAs()` fails. Better, pass the resolved CA ID from the issuer lookup into the status lookup instead of resolving twice.

---

## UNVERIFIED findings

| ID | Sev (if real) | file | Issue | preconditions → yields |
|---|---|---|---|---|
| SEMGREP-005 | HIGH | ui/package-lock.json (react-router 6.0.0-7.18.1, GHSA-49rj-9fvp-4h2h) | turbo-stream deserialization leading to RCE. This only applies when react-router data/SSR (server loaders) is used. The UI is a Vite SPA, so the advisory is probably not exploitable, but the bundle was not checked. | can send requests to SSR endpoint → RCE on SSR host |
| SEMGREP-006 | CRITICAL (npm label) | ui/package-lock.json (proxy-addr 1.1.0-2.0.7, GHSA-jqcg-44mw-7w3h) | IP spoofing through trust-subnet matching. Pulled in transitively, probably via @modelcontextprotocol/sdk or express dev tooling. Not shipped in the hub, which is Go, so likely not exploitable. Confirm with `npm ls proxy-addr`. | none for hub |
| SEMGREP-007 | MEDIUM | internal/bootstrap/siem_integration.go:218,252 | The SIEM webhook URL and syslog addr are dialled with no egress guard. Who can set them (config/admin) was not traced. | config write → SSRF/port probe |
| SEMGREP-008 | MEDIUM | internal/bootstrap/authz_write_gate.go:252 | The gate only covers POST/PUT/PATCH/DELETE. A GET (or HEAD/OPTIONS) handler that mutates state would bypass it. No GET handlers were audited for side effects. | authenticated viewer → unauthorized write via GET |
| SEMGREP-009 | LOW | internal/bootstrap/authz_write_gate.go:252,130 | The gate matches the decoded `r.URL.Path` exactly and case-sensitively, and skips anything not prefixed `/api/v1/`. That is safe with Go's case-sensitive ServeMux. It would be a bypass if any router mounts API writes outside `/api/v1/` or normalizes case or `%2F` differently. Mount points beyond the list in the gate's comment were not enumerated. | authenticated low-priv → ungated write |
| SEMGREP-010 | MEDIUM | internal/bootstrap/handlers_spiffe.go:208,215; spiffe_workload.go:189 | Responses return `key_pem`, a server-generated private key. This may be by design for SVID issuance, but it breaks the "key never leaves boundary" rule unless the requester is the workload itself. Response caching, audit logging and TLS-only delivery were not verified. | certificate.issue → private key of issued SVID |
| SEMGREP-011 | LOW | internal/bootstrap/agent_attestation.go:58 | `KRYPTKEEPER_AGENT_OPEN_REGISTRATION=true` lets anyone who can reach the hub enrol an agent. The routes are permSelf in the gate. The default was not verified. | network reach to hub + flag set → agent identity (chains with agent routes) |

| SEMGREP-014 | LOW | internal/acme/server.go:896-899 | `resolveIssuingCAID` returns `(s.caID, true)` when `ListCAs()` errors, so an ACME revocation during a CA-store error is written against the default CA, not the issuing CA. The issuing CA's CRL/OCSP would then not list the revocation. The comment says this is intended ("no better answer exists"); failing the revoke would be safer. Not traced whether the caller reports success. | ACME revoke during transient DB error → revocation silently ineffective for the real issuer |
---

## False positives (triaged)

| Group | Location(s) | Reason |
|---|---|---|
| SQL built with `fmt.Sprintf` | approval_store.go:222-239, inventory_source.go:368-426, connector_store.go:110-148, pending_action_store.go:90-165, handlers_ssh_certs.go:85,101, tenant_store.go:81,110, ha_coordinator.go:137 | Only dialect placeholders (`s.ph(n)`) and constant column lists are interpolated. Values are bound args. |
| SQL `+ whereSQL` | discovery_db_provider.go:1015,1177,1623,1741; dashboard_action_db_provider.go:112,238 | `where` clauses are constant strings with `?` placeholders (e.g. `"e.protocol = ?"`), and args are bound. |
| `"SAVEPOINT "+name` | discovery_db_provider.go:780-790 | `name` is `fmt.Sprintf("sp_ep_%d", i)` (callers at :861 and :1469), an integer only. |
| InsecureSkipVerify in scanners | discovery/scanner/scanner.go:232, protocols.go:53, posture.go:118-149, cipheraudit/auditor.go:62 | Inspection handshakes whose purpose is to collect any presented certificate. No credentials are sent over them. |
| InsecureSkipVerify in agentinstall | agentinstall/verify.go:36 | The documented fingerprint verifier. The caller compares the fingerprint. |
| SHA-1 / MD5 / RC4 | cmp/protection.go:10, cmp/crmf.go:297, agentdiscovery/ntlm_session.go:10-11, agentinstall/iis.go:54, wstep/renewal_signer.go:22, cmd/kryptkeeper/main.go:12 | Protocol-mandated: RFC 4210 legacy MAC, MS-NLMP, the Windows thumbprint lookup key, and the RFC 6960 IssuerKeyHash. None is used for an authorization decision. |
| SHA1/MD5 signature checks | certificate_ca_provider.go:1205,1310,1408; discovery/scanner/scanner.go:541 | Detection or rejection of weak signatures, not use of them. |
| XML/ASN.1 parsing DoS/XXE | wstep/server.go:288 (128 KiB), xcep/server.go:106 (64 KiB), scep/server.go:259 (64 KiB), cmp/server.go:79 (128 KiB) | Every protocol body is wrapped in `http.MaxBytesReader`. Go's `encoding/xml` does not resolve external entities or DTDs. |
| Path traversal in agentinstall/plugins | agentinstall/executor_sudo.go:60 | Only `os.CreateTemp` was found. No attacker-controlled path joins exist in agentinstall/ or plugins/delivery. |
| Plugin outbound HTTP | plugins/delivery/host.go:255-282 | https only, userinfo rejected, per-plugin host allowlist re-checked on redirect. This is a good control. |
| `private_key_pem` struct tag | bootstrap/renewal_executor.go:56 | An inbound credential payload shape, stored encrypted (W5-10). Not a response field. |
| Engine: `bpm-owasp-a02-tls-verify-disabled-go` ×7 | agentinstall/verify.go:36; cipheraudit/auditor.go:61; discovery/scanner/posture.go:118,133,148; protocols.go:53; scanner.go:231 | Same sites as the first-pass InsecureSkipVerify groups: inspection handshakes that collect any presented certificate, and the fingerprint verifier. |
| Engine: `bpm-owasp-a02-weak-hash-go` ×3 | cmd/kryptkeeper/main.go:1100 (RFC 6960 IssuerKeyHash); agentdiscovery/ntlm_session.go:263 (MS-NLMP); agentinstall/iis.go:555 (Windows thumbprint) | Protocol-mandated identifiers, not security decisions. Already in the first-pass SHA-1/MD5 group. |
| Engine: `bpm-owasp-a07-hardcoded-secret-go` ×1 | bootstrap/auth_bootstrap.go:26 | `token := ""` is an empty initializer, filled from the Authorization header on the next lines. |
| Engine: `bpm-secret-generic-assignment` ×1 | bootstrap/outbound_credential_store.go:34 | `CredentialTypeWindowsPassword = "windows_password"` is an enum label, not a secret. |
| Engine: `bpm-secret-pem-private-key` ×1 | ui/src/pages/TargetSetup.tsx:124 | Input placeholder text `-----BEGIN OPENSSH PRIVATE KEY-----` with no key body; marked `secret-scan:allow`. |

React XSS sinks: the sweep of `ui/src` for `dangerouslySetInnerHTML`, `innerHTML=`, `window.location=` and `window.open(` returned no hits.

Authorization gate review (authz_write_gate.go):
- It fails closed: an unmatched `/api/v1/` write needs admin.
- mcp-agent gets no permissions beyond `propose`.
- The `*` API-key scope is limited to ops permissions.
- `/api/v1/auth/**` (login, logout, refresh, OIDC, SAML) and `/api/v1/agent/**` (register, heartbeat, inventory, renewal-result) are permSelf, and every registered route under them authenticates itself. No REAL bypass was found. The residual risks are SEMGREP-008 and SEMGREP-009.

Tenancy: there was not enough tool budget to trace tenant scoping through the stores, so tenancy is not covered here. It is handed to owasp-web-checker (A01).

## Engine run (opengrep + bpm-rulepacks)

- Engine: opengrep 1.30.2. Rules: bpm-rulepacks `packs/{owasp,secrets,slop,framework,house}` only.
- Targets: `cmd internal sdk plugins ui/src` (excludes node_modules, ui/dist; git-tracked files).
- Command (run from repo root; `LC_ALL=en_US.UTF-8` is REQUIRED, or the engine dies with a `UnicodeDecodeError` on UTF-8 in rule files):
  `LC_ALL=en_US.UTF-8 opengrep scan --config <packs>/owasp --config <packs>/secrets --config <packs>/slop --config <packs>/framework --config <packs>/house --sarif-output=docs/security/opengrep_2026-10-09.sarif --json-output=docs/security/opengrep_2026-10-09.json --exclude node_modules --exclude ui/dist cmd internal sdk plugins ui/src`
- Rules: 232 loaded, 80 applicable to this codebase (go 25, ts 44, multilang 11), over 713 files. 0 engine errors.
- Results: 288 total. 13 from security rules (owasp/secrets), all FP (see the engine rows in "False positives"). 275 from slop rules (see "Code-health (slop) results").
- framework/react rules (dangerous-html, unsafe-href, target-blank-noopener): 0 hits on ui/src, which agrees with the first-pass XSS sweep.
- New REAL from the engine pass: SEMGREP-012 and SEMGREP-013. Both came from manually tracing slop `fallback-hides-failure-go` hits in the OCSP path, not from a security rule.
- Outputs: `docs/security/opengrep_2026-10-09.sarif`, `docs/security/opengrep_2026-10-09.json`, `docs/security/opengrep_2026-10-09.log`.

## Code-health (slop) results

For the code-review pass. These are not security findings unless noted. Paths are relative to `internal/` unless they start with `cmd/` or `ui/`. Full hit list: `docs/security/opengrep_2026-10-09.json`.

| Rule / shape | Count | Where | Disposition |
|---|---|---|---|
| empty-catch-go: `_, _ = w.Write(...)` | 79 | bootstrap handlers | FP. Standard HTTP response-write idiom; nothing useful to do on a failed write. |
| empty-catch-go: `ALTER TABLE ... ADD COLUMN` with ignored error | 26 | bootstrap/agent_store_db.go:73-81; discovery_db_provider.go:714-725 and 1419-1426 (duplicated block); managed_target_store.go:245,259 and 319,333 (duplicated); pending_action_store.go:72; pqc_wave_store.go:104; audit_db_provider.go:221; db/migrate.go:532 | **UNVERIFIED, worth review.** Swallows every error, not only duplicate-column. A DB outage or permission error silently skips the upgrade, and the failure surfaces later as a confusing query error. Check for the duplicate-column error specifically and fail otherwise. De-duplicate the two copies in discovery_db_provider.go and managed_target_store.go. Security note: the skipped columns include `agents.token_hash`, `pending_actions.tenant` and `audit_log.tenant`; queries that use them would error (fail closed), so no bypass was found. |
| empty-catch-go: best-effort cleanup/rollback `exec.Run`, `e.Run`, `s.soap`, `tx.ExecContext` RELEASE SAVEPOINT (incl. 2 deferred) | 13 | agentinstall/haproxy.go:77,92,98; installer.go:177,188,194; iis.go:390,453,602; keychain.go:118; executor_ssh.go:191; agentdiscovery/agentless_winrm.go:342; bootstrap/discovery_db_provider.go:787 | FP. Each is commented best-effort after the primary error is already returned. |
| empty-catch-go: `rand.Read`, `mac.Write`, `io.Copy` drain, `conn.Write`, `io.WriteString`, `fmt.Fprintln` | 10 | agentdiscovery/agentless_winrm.go:125; bootstrap/discovery_db_provider.go:497; winrm_sealed.go:195; others | FP. `crypto/rand.Read` and `hash.Write` do not return errors in practice; the rest are drains and protocol best-effort writes. |
| fallback-hides-failure-go | 110 | bootstrap 53, acme 10, keystore 10, ca 7, wstep 7, others | Mostly typed-zero returns on lookup or parse failure. Checked by hand and **fail-closed** (FP for security): handlers_tenants.go:45,109 (deny), auth_oidc_login.go:576 scimAuthorized, auth_identity.go:205,209 jwtRoleClaim, handlers_credentials.go:80, wstep/renewal_signer.go:80-130 (signature verify returns nil/false), xcep/server.go:340, keystore/mldsa.go (error-propagating), certificate_ca_provider.go:1248. **Security-relevant:** cmd/kryptkeeper/main.go:1059,1075 → SEMGREP-012/013; acme/server.go:898 → SEMGREP-014. Hand the rest (e.g. evidence_schedule_store.go:49 `isDue` returns true on a bad timestamp, which could resend evidence every tick; middleware_request_id.go:62 `"req_fallback"`; cbom_export.go:84 nil UUID; handlers_agents.go:307 empty task ID on RNG failure) to review-code. |
| step-by-step-narration-go | 19 | acme/server.go:921-1030; ca/hybrid_cert.go:20-125 | Comment style; no verdict. |
| emoji-in-comments-go | 2 | ca/hybrid_cert.go:16,17 | Comment style; no verdict. |
| delegation-only-wrapper-go | 5 | adsync/ldap_client.go:123; agentinstall/executor_ssh.go:111; metrics/metrics.go:26; plugins/delivery/runtime.go:67,119 | Possible interface adapters; review-code to confirm. |
| ui empty-catch | 4 | ui/src/lib/api.ts:274,307,336,848 | FP. JSON-body parse on error responses, falling back to the status-text message. |
| ui try-catch-in-loop | 4 | ui/src/lib/bulk.ts:43; pages/Certificates.tsx:731,780; pages/PQCMigration.tsx:345 | FP. Per-item error collection in bulk operations, by design. |
| ui fallback-hides-failure / try-parse-fallback / redundant-null-check | 3 | pages/Certificates.tsx:625; pages/Integrations.tsx:52; lib/api.ts:382 | Low priority; review-code. |

## Completion Manifest
- Produced (first pass): docs/security/SEMGREP_FINDINGS_2026-10-09.md, docs/security/govulncheck_.txt, docs/security/govulnchecksdk.txt, docs/security/govulncheckplugins.txt, docs/security/npm-audit.json
- Produced (engine pass): docs/security/opengrep_2026-10-09.sarif, docs/security/opengrep_2026-10-09.json, docs/security/opengrep_2026-10-09.log; this file updated in place
- Counts: REAL 8 (C0 / H0 / M5 / L3), of which NEW from the engine pass 2 (M1 SEMGREP-012, L1 SEMGREP-013); UNVERIFIED 8 (+1 SEMGREP-014); FP 11 + 5 groups; slop 275 bucketed
- Engine: opengrep 1.30.2 + bpm-rulepacks (owasp, secrets, slop, framework, house); 232 rules loaded, 80 applicable, 713 files, 0 errors. ast-grep not installed, so astgrep rules did not run.
- Memory written: None (memory tool deferred; tool-call cap).

### Addendum (coordinator): ast-grep rules

ast-grep 0.45.3 was installed and the bpm-rulepacks `astgrep/` rules were run. The pack has no Go rules; its 13 TypeScript/JavaScript rules ran over ui/src: **3 matches, all `bpm-house-unbounded-response-read` (warning)** at ui/src/lib/api.ts:285, :315 and :862. These read the hub's own API responses (`res.json()` / `res.text()`) without a size cap. Code-health LOW, not a security finding: the peer is the operator's own hub, behind the same session. Left for the code-review pass.
