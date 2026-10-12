# LLM Findings: OWASP LLM Top 10 (2025) for the MCP surface, 2026-10-09

- Scope: `cmd/kryptkeeper-mcp`, `internal/mcpserver` (mcp-go v0.55.0), and the Hub endpoints those tools reach (`internal/bootstrap`).
- Product LLM calls: none. The LLM surface is the MCP server that third-party agents drive.
- Read first: `docs/security/SEMGREP_FINDINGS_2026-10-09.md`. DEP-001 (stdlib http2 reachable via `mcpserver.ServeHTTP`) and SEMGREP-008/010 are not repeated here.

## Summary

| ID | Sev | Category | File:line | Title |
|---|---|---|---|---|
| LLM-001 | HIGH | LLM06/LLM06b, LLM02 | internal/bootstrap/handlers_audit.go:17-20 | `audit_query` returns the cross-tenant audit log with no read authorization |
| LLM-002 | MEDIUM | LLM02/LLM06b | internal/bootstrap/handlers_search.go:30,46 | `search` tool returns certificates and CAs from every tenant |
| LLM-003 | MEDIUM | LLM01 (indirect) | internal/mcpserver/server.go:26-31 | Tool results are raw Hub JSON with no untrusted-data boundary |
| LLM-004 | MEDIUM | LLM10/LLM06 | internal/mcpserver/transport_http.go:29-33 | HTTP transport has no auth, no Origin/Host check (DNS rebinding) and no body cap |
| LLM-005 | MEDIUM | LLM10 | internal/bootstrap/handlers_pending_actions.go:64-79 | Proposal body is unbounded and stored verbatim |
| LLM-006 | LOW | LLM06 | internal/bootstrap/handlers_pending_actions.go:77,164 | proposer != approver binds the shared MCP token, not the human driving it |

Totals: REAL 6 (C0 / H1 / M4 / L1). UNVERIFIED 2. INFO 1.

---

## REAL findings

### LLM-001: `audit_query` returns the cross-tenant audit log with no read authorization
- severity: HIGH | category: owasp-llm (LLM06 excessive agency, LLM06b confused deputy, LLM02 disclosure)
- file: internal/bootstrap/handlers_audit.go:17-20 (also internal/mcpserver/server.go:144-151, internal/bootstrap/audit_db_provider.go:77)
- evidence:
  - The handler calls `auth.AuthenticatePrincipal(r, ...)` and then lists entries. It does no role, permission or tenant check.
  - Nothing else checks it. The only middleware is `withRequestID(withAPIRateLimiting(withWriteAuthorization(...)))` (server.go:92), and the write gate ignores GET (SEMGREP-008). `/audit` is not on the rate-limited list (ratelimit_mw.go:33-41).
  - The declared permissions for mcp-agent are `certificate.read` and `action.propose` (authz_custom_roles.go:313). Audit read is an undeclared, implicit grant.
  - `AuditListQuery` has no tenant field. `audit_db_provider.go` selects `tenant` but never filters on it (:77, :176). The handler is given the bare principal, not `AuthPrincipal`, so it has no tenant to apply.
  - Fields returned (audit_provider.go:25-38) include `actor_id`, `source_ip`, `user_agent`, `session_id` (the client-supplied `X-Session-Id`, audit_events.go:44), `change_summary` and `tenant`.
  - The MCP tool passes only `limit`, capped at 100 (audit_provider.go:101), and no cursor. Through MCP this gives the latest 100 entries on each call, not a bulk export. The raw token can page with `cursor`.
- preconditions: "MCP tool access (stdio client, or any caller reaching the HTTP transport, see LLM-004), or the mcp-agent token itself; multi-tenancy enabled for the cross-tenant part"
- yields: "operator identities, source IPs, user agents, session ids and change summaries across all tenants; reconnaissance of who approves and when (useful for timing a malicious proposal); attacker-influenced audit text flows into the agent context (LLM-003)"
- asset: audit log confidentiality, tenant isolation
- status: REAL, proven by reading the code. The Hub handler is shared with human roles, so A01 (owasp-web-checker) should cross-reference it. It is kept here because a named MCP tool reaches it.
- remediation: In handlers_audit.go, use `AuthenticatePrincipalDetails`, require an `audit.read` permission that mcp-agent does not hold (or drop `audit_query` from the MCP tool set), and add a tenant predicate to `AuditListQuery` and the DB provider.

### LLM-002: `search` tool returns certificates and CAs from every tenant
- severity: MEDIUM | category: owasp-llm (LLM02, LLM06b)
- file: internal/bootstrap/handlers_search.go:30,46 (tool: internal/mcpserver/server.go:69-80)
- evidence:
  - `/api/v1/search` uses `AuthenticatePrincipal` only.
  - It calls `certProvider.ListCertificates(ctx, CertificateListQuery{Q: q, Limit: 10})` and `caProvider.ListCAs(ctx, CAListQuery{Limit: 50})` with no tenant filter.
  - By contrast, `/api/v1/certificates` applies `listCertificatesTenantFiltered` for tenant-scoped principals (handlers_certificates.go:235-238). Search skips that filter.
  - The output is bounded (10 certs, 50 CAs per query) but repeatable with chosen `q`.
- preconditions: "MCP tool access; multi-tenancy enabled"
- yields: "other tenants' certificate inventory (CN/SAN/fingerprint/issuer) and full CA list; no key material (CA objects expose key_storage_type/key_id references only, ca_provider.go:31,99)"
- asset: tenant isolation, inventory confidentiality
- status: REAL, proven by reading the code. Cross-reference A01.
- remediation: Pass `AuthPrincipal` into search and reuse the tenant-filtered list paths.

### LLM-003: Tool results are raw Hub JSON with no untrusted-data boundary
- severity: MEDIUM | category: owasp-llm (LLM01 indirect prompt injection)
- file: internal/mcpserver/server.go:26-31 (`mcp.NewToolResultText(string(body))`)
- evidence:
  - Every read tool returns the Hub body verbatim, with no framing that marks the content as untrusted data and no field stripping.
  - Attacker-influenced strings reach the model through several paths:
    - Subject CN, SANs and O of discovered certificates. Anyone running a TLS endpoint in a scanned range picks these strings.
    - The import `notes` field (certificate_provider.go:158).
    - Audit `change_summary` and `user_agent` (LLM-001). The user agent is set by any HTTP client.
    - Other principals' `rationale` and `params`, via `list_pending_actions` (writetools.go:208-216).
  - Sinks the injected text can steer: `propose_bulk_revoke` (revoke every cert of a CA), `propose_revoke`, and `propose_issue` with attacker-chosen CSR, CA, template and team. The agent also writes the `rationale` that the human approver reads.
  - Mitigations credited: every sink is a pending action that needs a pki-admin or pki-operator approval and refuses self-approval. No sink reaches a direct write, a key, a credential or an approval.
- preconditions: "attacker controls a cert subject/SAN on a discovered endpoint, or can import a cert with notes, or can send any HTTP request to the Hub (user_agent in audit); an operator asks an agent to triage inventory/audit"
- yields: "attacker-steered pending actions (e.g. bulk_revoke of a production CA) with an AI-authored, persuasive rationale placed in front of a human approver: an approver social-engineering primitive, not a direct write"
- asset: approval-queue integrity, availability of revocation targets
- status: REAL as a design gap (the data path is proven by reading the code). Impact is bounded by the human queue.
- remediation:
  - Wrap tool output in an explicit untrusted-data envelope (for example `{"untrusted_data": ...}` plus a tool description stating that content is data, not instructions).
  - Strip `notes`, `user_agent` and `change_summary` from MCP projections.
  - Label agent-originated proposals in the approval UI and show the computed blast radius (cert count for bulk_revoke) beside the rationale.

### LLM-004: HTTP transport has no auth, no Origin/Host check, and no body cap
- severity: MEDIUM | category: owasp-llm (LLM10 unbounded consumption, LLM06 agency exposure)
- file: internal/mcpserver/transport_http.go:29-33; mcp-go v0.55.0 server/streamable_http.go:346 (`io.ReadAll(r.Body)`), :443
- evidence:
  - `NewHTTPHandler` mounts `server.NewStreamableHTTPServer(srv)` with no authentication. This is documented, and the default bind is loopback `127.0.0.1:8080` (cmd/kryptkeeper-mcp/main.go:45).
  - mcp-go has no Origin or Host validation. The only `Origin` handling is in `http_cors.go`, which emits headers and is opt-in, and it is not configured here. The MCP spec requires servers to validate `Origin` to stop DNS rebinding.
  - Loopback binding therefore does not stop a page in the operator's browser from rebinding to 127.0.0.1. After rebinding the request is same-origin, so the `application/json` content-type check (:443) triggers no preflight.
  - The POST body is read with unbounded `io.ReadAll`. Only `ReadTimeout` 15s (transport_http.go:55) bounds it.
  - No per-client rate limit applies at the MCP layer.
  - The Hub limits proposals per principal (20/min) and `/reports/*` (60/min). All MCP clients share one principal, so a single abusive client exhausts the quota for legitimate agents. `/certificates`, `/search`, `/cas`, `/audit` and GET `/pending-actions` have no rate limit.
- preconditions: "KRYPTKEEPER_MCP_TRANSPORT=http, and either (a) operator on the same host visits an attacker page (DNS rebinding) or (b) listener exposed beyond loopback without a fronting proxy"
- yields: "full MCP tool capability under the server's token: inventory and cross-tenant audit/search reads (LLM-001/002), proposal creation; MCP-process memory exhaustion via large POST bodies; exhaustion of the shared per-principal proposal quota"
- asset: MCP token capability, MCP process availability
- status: REAL, proven by reading the code (transport_http.go and the vendored mcp-go source). The no-auth part is a documented, accepted risk. The rebinding and body-size parts are not mentioned in the docs.
- remediation:
  - Wrap the handler with an Origin/Host allowlist (reject when `Origin` is present and not allowlisted, and when `Host` is not the bind host).
  - Wrap it with `http.MaxBytesReader` (for example 1 MiB).
  - Add a bearer token check (`KRYPTKEEPER_MCP_HTTP_TOKEN`) so non-loopback deployments do not depend solely on a proxy.

### LLM-005: Proposal body is unbounded and stored verbatim
- severity: MEDIUM | category: owasp-llm (LLM10)
- file: internal/bootstrap/handlers_pending_actions.go:64-79
- evidence:
  - The handler does `json.NewDecoder(r.Body).Decode(&req)` with no `http.MaxBytesReader`. Sibling handlers all cap their bodies (handlers_approvals.go:283 at 4 KiB, handlers_agility.go:71 and others).
  - Only `ActionType` is validated at create time (pending_action_exec.go:193-198).
  - `Params` (json.RawMessage) and `Rationale` are stored as-is and rendered to approvers.
  - The rate limit (ratelimit_mw.go:15, 20 POST/min per principal) bounds the number of proposals, not their size. Nothing caps queue depth or deduplicates.
- preconditions: "any authenticated principal holding action.propose, including the mcp-agent token or a prompt-injected agent (LLM-003)"
- yields: "DB/storage growth and approval-UI degradation (multi-MB rationales and params); approver fatigue from up to 28,800 proposals/day/principal, which buries legitimate proposals"
- asset: Hub storage, approval-queue usability
- status: REAL, proven by reading the code.
- remediation: Add `http.MaxBytesReader(w, r.Body, 64<<10)`, cap `Rationale` length, validate `Params` against the action type at proposal time, and cap open proposals per proposer.

### LLM-006: proposer != approver binds the shared MCP token, not the human driving it
- severity: LOW | category: owasp-llm (LLM06)
- file: internal/bootstrap/handlers_pending_actions.go:77 (`ProposedBy: pd.ID`), :164
- evidence:
  - The proposer is recorded as the MCP token's principal ID. The self-approval check compares that ID to the approver.
  - A pki-operator can direct an agent to propose an action and then approve it from their own dashboard session. The two-person rule holds per identity, not per human.
  - The control's stated purpose holds: the AI identity can never approve (see Verified controls).
- preconditions: "a human approver also operates the MCP client"
- yields: "single-human end-to-end destructive action (revoke/bulk_revoke/issue) with the audit trail showing an agent proposer and a different approver"
- asset: separation of duties
- status: REAL by design. Low severity because it needs an insider who already holds approval rights.
- remediation: Pass the end-user identity to the Hub (for example a signed `X-On-Behalf-Of` from an authenticated MCP client) and refuse approval when it matches. At minimum, flag same-human proposals in the UI.

---

## UNVERIFIED

| ID | Sev (if real) | file | Issue | preconditions -> yields |
|---|---|---|---|---|
| LLM-U1 | MEDIUM | internal/bootstrap/pending_action_exec.go (executePendingAction) | Proposal `params` (ca_id, fingerprint) are not tenant-checked at create time. Whether execution checks that the CA or cert belongs to `action.Tenant` was not traced. | tenant-A agent proposes bulk_revoke of tenant-B CA -> cross-tenant revoke if a super-admin approves |
| LLM-U2 | LOW | ui approval view | Whether the approver sees the blast radius (number of certs a bulk_revoke hits) before approving was not checked. | injected agent proposal -> uninformed approval |

## INFO

- internal/bootstrap/mcp_role.go:17-23 says the boot-time refusal of an approver-capable token "remains unimplemented and unticketed (G-58)". It is in fact implemented at cmd/kryptkeeper-mcp/main.go:99-118 (`CheckSelfRole`, fail-closed). The comment is stale.

## Verified controls (no finding)

- **The MCP identity cannot approve, by construction.**
  - `canApproveActions` returns false for `RoleMCPAgent` before any allowlist check (handlers_pending_actions.go:22-25).
  - The approve path (:154) and the reject path (:139) both use it.
  - Self-approval is refused (:164).
  - Tests pass: `TestCanApproveActions_MCPAgentRoleRejected`, `TestPendingActions_MCPAgentRoleCannotApproveOrReject`, `TestPendingActions_ProposerCannotSelfApprove`, `TestApprovalApproveRefusesSelfApproval`, `TestNHISelfApprovalRefused` (`go test ./internal/bootstrap/ -run ...`, ok 2026-10-09).
- **No write reach.** `principalPermissions` returns an empty set for mcp-agent (authz_write_gate.go:180-182). The write gate allows mcp-agent only POST `/api/v1/pending-actions` (:230, :275).
- **Misprovisioning detection.** `cmd/kryptkeeper-mcp` refuses to start if `/protected/whoami` reports `can_approve_actions`, and also refuses if the Hub is unreachable (main.go:110-118). Tests: `TestProtectedWhoami_ReportsRoleAndCanApproveActions`, `go test ./internal/mcpserver ./cmd/kryptkeeper-mcp` ok.
- **Write tools are proposal-only.** The 5 write tools call only `hub.post("/pending-actions")` (writetools.go:32), and their action types are fixed in code.
- **No key or credential reach.** No MCP tool hits a key, credential, connector, backup or SPIFFE endpoint, so SEMGREP-010 `key_pem` is not reachable through MCP tools. The certificate and CA JSON carries no private material (only `key_id`/`key_storage_type` references).
- **No path injection.** `get_certificate` uses `url.PathEscape`, and query args go through `url.Values.Encode`.
- **Hub list limits.** The Hub caps `limit` at 100 for certificates and audit (handlers_certificates.go:249, audit_provider.go:101).
- **LLM05 (improper output handling): no finding.** The server has no eval, exec, template or shell sink for tool output. The Hub validates params at execution time, not at proposal time (see LLM-005).
- **Hub response size is capped.** Hub responses are limited to 8 MiB by `io.LimitReader` (hubclient.go:59, :118). Hub 4xx bodies are echoed into tool errors (hubclient.go:66), which is low risk because those are Hub-authored messages.
- **Not applicable:** LLM03 supply chain (model), LLM04 data poisoning, LLM07 system prompt leakage, LLM08 vector/embedding and LLM09 misinformation. The product runs no model, prompt, RAG or embeddings. The mcp-go dependency is covered by DEP-001.

---

# Completion Manifest

## Files produced
- `docs/security/LLM_FINDINGS_2026-10-09.md`: OWASP LLM Top 10 assessment of the MCP surface. 6 REAL, 2 UNVERIFIED, 1 INFO.

## Files modified
- None

## Decisions made
- LLM-001 is rated HIGH, not MEDIUM. A named MCP tool reaches cross-tenant operator metadata that falls outside the role's declared permissions. It is not CRITICAL because it exposes no keys, credentials or writes.
- The Hub-side tenancy gaps (LLM-001, LLM-002) are kept in this file because MCP tools reach them. They are flagged for A01 cross-reference.

## Known issues / deferred
- Tenant scoping in the executor (LLM-U1) was not traced because of the tool-call cap.
- The DNS-rebinding finding was proven by reading the source, not by a live exploit.

## Verify result
- PASS: each REAL finding cites file:line and code read during this session. The approval controls were proven by passing tests. Evidence: `docs/security/LLM_FINDINGS_2026-10-09.md`

## Memory written
- None. Nothing durable beyond this report.
## Model tier: large, estimated context used: medium

Maker: owasp-llm-checker
Verifier: advisor review (independent model)

## Ready for: attack-chainer

owasp-llm done --
