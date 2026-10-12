# Kryptkeeper — SRS Review Addendum (design-review arc)

**Date:** 2026-07-15 · extends `docs/sdlc/phase-2-requirements/SRS.md` with requirements for the
P2-adopted amendments (DECISIONS D-022..D-039). New IDs use the `FR-R<n>` / `NFR-R<n>` namespace
so they never collide with the base SRS (FR-001..FR-102, NFR-001..). Each row carries an
**acceptance sketch** that its board ticket's acceptance must map to a named test (per TEST_STRATEGY).
`ALL of {...}` is written literally where a set is meant (L-03).

## Functional requirements

| ID | Requirement | Acceptance sketch | Traces |
|---|---|---|---|
| FR-R1 | UI lint + unit test lanes execute in CI against the real `ui/` tree with npm | a PR touching `ui/**` runs eslint + vitest; a seeded lint error fails the PR | D-024, G-1, R-A1 |
| FR-R2 | Nightly gate runs real, existing test suites | nightly job runs `tests/{smoke,integration,protocol}` + `go test ./...`; no step targets a nonexistent path | D-024, G-25, R-A3 |
| FR-R3 | `openapi.yaml` matches the served route set and is CI-validated | every registered `/api/v1` route has a path+operationId; a route with no spec entry fails the OpenAPI CI job | D-024, G-5, R-A4 |
| FR-R4 | Tenant binding is identity-derived, not header-asserted | with `MULTI_TENANCY=on`, a scoped principal's tenant comes from JWT/OIDC claim or api_key/user record; `X-Tenant` is honored ONLY for super-admin view-as; a scoped principal setting `X-Tenant` to a non-member tenant is denied | D-025, G-12, R-B1 |
| FR-R5 | Tenant enforcement covers ALL of {list reads, single-resource GETs, create, update, delete} for ALL of {certificates, CAs, templates, approvals}. **Pending-actions is already enforced** (list `handlers_pending_actions.go:45` + decide `:107` + proposer-tenant stamped `:62`) and gains a regression test rather than new enforcement | for each resource×verb, a cross-tenant scoped request returns 403/404; a new CA/template auto-maps to the creator's tenant; a regression test proves pending-actions stays isolated | D-026, R-B2 |
| FR-R6 | Reports and dashboard respect tenant scope (or are explicitly super-admin-only), via one shared scope helper applied across ALL report handlers. Ownership: W2-03 builds the helper + wires the api-lane report families {crypto-posture, ca-health, expiry, revocation, issuance, change-audit, compliance, algorithm-sunset, dashboard, posture-trend, executive-summary, evidence, pqc-countdown, pqc-migration}; the two core-lane report endpoints apply it in their owning tickets — **pqc-waves in W2-08, renewal-slo in W2-07** | a scoped principal's report/dashboard responses reflect only their tenant across ALL families above, OR return 403 with the aggregate-super-admin ADR cited | D-027, R-B3 |
| FR-R7 | Audit rows record tenant context | every audited action stores `tenant` and, for view-as, `acting_as_tenant`; a header-switched action is distinguishable in the trail | D-028, R-B4 |
| FR-R8 | The MCP/agent identity cannot approve pending actions | an MCP token cannot pass `canApproveActions` by construction (constrained role) or the MCP server refuses to boot with an approver-capable token | D-029, R-C1 |
| FR-R9 | Proposal and report endpoints are rate-limited | `/pending-actions` (write) and `/reports/*` enforce a per-principal limit; exceeding it returns 429 | D-030, R-C2 |
| FR-R10 | Findings pass a stamped funnel with justified, expiring suppression (v0.9: exception/suppression half deferred to v0.10; hidden in UI) | a finding surface shows `raw → deduped → in-scope → effective → suppressed(justified)`; an accepted-risk exception carries a fixed-enum justification + expiry and auto-reopens when the cert is re-issued or the exception lapses; raw counts are never hidden | D-031, R-D1 |
| FR-R11 | Discovery dedups and ages findings using the existing schema | a re-scan upserts `endpoints` on `(ip,port,sni)` (no duplicate rows); `certificate_endpoints.last_seen`/`currently_active` are written; a cert not re-observed is marked gone | D-032, R-D2 |
| FR-R12 | Expiry alerts dedupe and can be silenced per target | `alert_cooldown_hours` is enforced (same cert not re-alerted within the window); a rule can target/silence a specific cert/CA/template | D-033, R-D3 |
| FR-R13 | Renewal-trigger failures are retried and escalated, not just logged | a failed auto-renewal trigger enters a retry budget then a dead-letter/escalation surface visible in the renewal-SLO report | D-034, R-E1 |
| FR-R14 | Migration waves carry a stored lifecycle | a wave row has status ∈ {proposed, accepted, in_progress, done, regressed}; a regression is recorded, not only recomputed at read | D-035, R-E2 |
| FR-R15 | UI SAN rendering reads the wire field | cert detail renders DNS SANs from `subject_alt_names`; a fixture built from the wire (not the client type) covers it | D-037, G-10 |
| FR-R16 | Agent auth tokens are hashed at rest with constant-time compare | stored agent tokens are non-reversible; comparison is constant-time; a plaintext-token row fails a migration check | D-037, G-28 |
| FR-R17 | MCP server ships with an HTTP transport and a container image | `cmd/kryptkeeper-mcp` supports HTTP/StreamableHTTP; Dockerfile builds+ships the mcp binary; the stale "read-only, no mutation path" comment is corrected | D-037, G-29 |

## Non-functional requirements

| ID | Requirement | Basis | Traces |
|---|---|---|---|
| NFR-R1 | CI is real: a "green" gate requires ≥1 successful runner-executed run, not just a registered workflow | L-06 (0 runs ever) | D-023, HP-2 |
| NFR-R2 | The API surface is contract-tested: fixtures derive from the OpenAPI contract, never from client types | L-03 (fixture drift) | FR-R3 |
| NFR-R3 | Tenant isolation is enforced at the identity layer, not opt-in by the client | P2 tenancy finding | FR-R4/R5 |
| NFR-R4 | Signals not grades on findings: raw counts are always shown alongside effective; suppression is justified and auto-reopens | Shipwright GATE_ECONOMICS / RepoPulse VEX | FR-R10 |
| NFR-R5 | Module boundaries have a lint config (golangci-lint) even before the bootstrap split | G-13, D-038 | FR-R1 kin |
