# OWASP_WEB_FINDINGS 2026-10-09 (kryptkeeper, --deep) — PARTIAL

Status: PARTIAL. Three category sub-audits (A01 gate/tenancy, A02+A07, A03+A08+A10) were dispatched but had not returned when this run was forced to hand back. Their categories are NEEDS_REVIEW in OWASP_TRACKER.md. Only findings below were verified by this agent against code.
Dedup baseline: SEMGREP-001..011, DEP-001/002, SEC-01..04 are not re-raised.

## REAL findings

### OWASP-001: Audit source IP taken from client-supplied X-Forwarded-For
- severity: LOW | category: owasp-web | tool: manual | status: REAL
- file: internal/bootstrap/audit_events.go:72
- evidence: extractSourceIP returns the leftmost X-Forwarded-For value whenever it is present, with no trusted-peer check. The shipped ./nginx.conf:20 sets only X-Real-IP, so a client's own XFF reaches the hub unchanged. Contrast auth_rate_limit.go:144-151, which deliberately refuses XFF.
- preconditions: ["can send HTTP requests to hub"]
- yields: ["forged source IP in audit entries (login failures, denied writes)"]
- asset: audit trail integrity
- remediation: Reuse the trusted-proxy clientIP() from auth_rate_limit.go in extractSourceIP.

### OWASP-002: Audit tenant attribution taken from raw X-Tenant header, including on unauthenticated requests
- severity: LOW | category: owasp-web | tool: manual | status: REAL
- file: internal/bootstrap/audit_events.go:59 (used at :46)
- evidence: auditRequestTenant uses the X-Tenant header without the principal's resolved tenancy. Failed-login audits (handlers_auth.go:74-88) run before any principal exists, so an unauthenticated caller can file audit events under any tenant when MULTI_TENANCY is on.
- preconditions: ["MULTI_TENANCY enabled", "can send HTTP requests to /api/v1/auth/login"]
- yields: ["write access to another tenant's audit log (noise/injection)"]
- asset: per-tenant audit trail
- remediation: Stamp the audit tenant from the resolved AuthPrincipal, and use DefaultTenant for unauthenticated events.

### OWASP-003: No browser security headers on hub or shipped proxy
- severity: LOW | category: owasp-web | tool: manual | status: REAL
- file: internal/bootstrap/server.go:120 (handler chain); nginx.conf (no add_header)
- evidence: Searches of internal/, cmd/ and nginx.conf for Content-Security-Policy, X-Frame-Options, frame-ancestors, nosniff and Strict-Transport returned no hits.
- preconditions: ["victim admin visits attacker page"]
- yields: ["UI clickjacking framing", "no HSTS downgrade protection"]
- asset: admin UI session
- remediation: Add a header middleware that sets CSP frame-ancestors 'none', nosniff and HSTS.

### OWASP-004: Session cookie Secure flag depends on X-Forwarded-Proto
- severity: LOW | category: owasp-web | tool: manual | status: REAL
- file: internal/bootstrap/handlers_auth.go:429
- evidence: `Secure` is set only when X-Forwarded-Proto is "https". A hub serving TLS directly (srv.TLSConfig != nil, server.go:178) issues kk_token without Secure.
- preconditions: ["hub deployed with native TLS and no proxy", "network MITM able to induce an http:// request"]
- yields: ["valid session token"]
- asset: kk_token session
- remediation: Set Secure when r.TLS != nil OR the forwarded proto is https, or always when TLS is configured.

## Checked, no finding
- CSRF: the kk_token cookie fallback (auth.go:285) is mitigated by SameSite=Strict (handlers_auth.go:428). No CSRF token exists, so the residual risk is same-site only.
- CORS: no Access-Control-Allow-* headers anywhere, so the browser default applies.
- /metrics is unauthenticated (cmd/kryptkeeper/main.go:853) but exposes only aggregate counters with no labels (internal/metrics/metrics.go:118-131). INFO.
- Server: ReadHeaderTimeout is set (server.go:94,123). Login, refresh and denied writes are audited (handlers_auth.go:74-197, authz_write_gate.go:271). There is a signed Merkle audit log (internal/audittrust).
- A06: covered by DEP-001/DEP-002. The sdk/ and plugins/ govulncheck gap remains, per SEMGREP_FINDINGS.

## Not covered (pending sub-audit results)
A01 gate bypass (encoded paths, method smuggling, non-/api/v1 mounts, permSelf routes), tenancy/IDOR, SEMGREP-008/009/010/011 resolution; A02 key egress/JWT/keystore; A07 login/refresh/OIDC/SAML/API keys/proposer!=approver; A03/A08 protocol parsers, CSR policy, plugin signatures; A10 SSRF beyond SEMGREP-001/002.

# Completion Manifest
## Files produced
- docs/security/OWASP_WEB_FINDINGS_2026-10-09.md — partial findings (4 LOW)
- docs/security/OWASP_TRACKER.md — per-category confidence
- docs/work/TASKS_owasp-web-checker-2026-10-09.md — task ledger (mandated by agent rules)
## Files modified
- None
## Decisions made
- Category deep-dives were delegated to 3 parallel agents to fit the tool cap. The forced handback came before their results arrived, so those categories are marked NEEDS_REVIEW rather than guessed.
## Known issues / deferred
- A01, A02, A03, A07, A08 and A10 need a re-run or the agents' results merged.
## Verify result
- PARTIAL — each finding is checked against the cited file:line — evidence: `docs/security/OWASP_WEB_FINDINGS_2026-10-09.md`
## Memory written
- None — nothing durable
## Model tier: large — low
Maker: owasp-web-checker
Verifier: none (pending)
## Ready for: owasp-web-checker re-run (merge sub-audit results), then attack-chainer
owasp-web done -- PARTIAL
