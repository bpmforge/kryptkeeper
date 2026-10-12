# Kryptkeeper — Field Lessons Ledger

One row per lesson; details below for the non-obvious ones. This file is the analyzable
input for (a) Kryptkeeper product features/tickets, (b) bpm-opencode-experts process/check
upstreams, (c) harness fixes. Append-only; stable L-ids.
**Route-to** values: `product:<ticket/FR>` · `experts:<protocol/validator>` · `harness` ·
`process`. **Status**: `shipped` / `ticketed` / `open`.

| ID | Date | Class | Lesson (one line) | Route to | Status |
|---|---|---|---|---|---|
| L-01 | 07-15 | ci-fail-open | A `hashFiles()` job condition on a wrong path (`web/` vs `ui/`) made the UI lint+test lanes silently skip for months while CI read green — path-gated jobs need an else-fail branch or an existence assertion | product: G-1 ticket; experts: CI-review check "every conditional job has a must-run counterpart" | open (check candidate) |
| L-02 | 07-15 | doc-lifecycle | Six scope docs still said "Scoping — not started" after their releases shipped and were tagged — release checklists must include re-statusing the scope doc, or the doc tree inverts into anti-truth | process: release checklist step added via DECISIONS D-018 canon; experts: release-mode step | shipped (this arc) |
| L-03 | 07-15 | fixture-drift | MSW fixtures mirrored the UI's (wrong) field names instead of the wire format, so tests passed while prod rendered empty (`sans` vs `subject_alt_names`) — fixtures must derive from wire truth (recorded/generated), never from the client's types | product: G-10 ticket; experts: test-engineer rule "fixtures from contract, not client" | open (ticketed) |
| L-04 | 07-15 | decision-drift | A locked decision (masscan two-phase discovery) silently diverged in the build (0 code refs) with no record — reconcile decided-vs-built at every release, and record deliberate divergences as amendments | process: DECISIONS.md amendment discipline (D-008); experts: challenger check "locked decisions vs code reality" | shipped (D-008 amendment) |
| L-05 | 07-15 | resume-docs | The handoff doc's own verify command curled routes that don't exist (`/api/v1/health/*` vs `/healthz`) — verify steps in resume docs must be paste-executable and verified at write time, since the next session trusts them blindly | process; experts: SESSION handoff template "verify commands are re-run before commit" | shipped (doc fixed) |
| L-06 | 07-15 | ci-phantom | CI can be fully configured and still have never run: 9 workflows registered "active" on the self-hosted forge, Actions enabled, badges renderable — but 0 runners and 0 runs ever. "Actions enabled" ≠ "a runner executes it." A green badge with no run behind it is worse than no badge. Verify runner + run history, not just config presence | product: G-2 confirmed / HP-2; experts: challenger check "CI-green claims need a run URL, not a workflow file"; process: release checklist asserts ≥1 successful run | open (check candidate) |
| L-07 | 07-15 | challenger-value | The challenger earned its cost: a GREEN traceability validator (22/22, no dangling refs) still hid 3 orphaned "ticketed" gaps, 2 subset loopholes, 4 seam holes, and 2 false factual claims (a var claimed unread that code reads; a dep claimed swappable that's transitive-only). ID-graph green ≠ complete/correct (L-05 recurrence). The maker≠verifier refute-mandate is not ceremony | process: challenger mandatory after every traceability green; experts: RALPH VERIFY + CHALLENGER already encode it | shipped (this arc) |
| L-08 | 07-16 | spec-premise-check | A ticket's acceptance criteria assumed a capability the architecture doesn't have (W4-02: "scheduler invokes issuance" assumed the hub can reissue a cert it tracks without a CSR/key from the holder — it can't, by design). Writing the spec/implementation surfaced this only after tracing the actual data flow (dead `RenewalMethod` values, separate ACME cert store). Board tickets written from acceptance-criteria pattern-matching (not code-verified) can encode a false premise that only implementation-time tracing catches — treat "can this literally be built as written" as its own pre-spec check, not just "is this in scope" | product: G-43 / re-scope W4-02; experts: spec-writing protocol add a premise-verification step before acceptance criteria are finalized | open (check candidate) |

## Details worth keeping (evidence pointers)

- **L-01**: `.github/workflows/ci-pr.yml` frontend jobs gate on `hashFiles('web/package.json')` + `pnpm --dir web`; repo has `ui/package.json` + npm lockfile. Dogfood run 2026-07-15: `npm --prefix ui run lint` → 4 errors (react-refresh, incl. `badge.tsx` which no backlog listed). The April fail-closed hardening (docs/ops/ws-10-*) fixed the *scripts* but not the *job conditions* — a second fail-open layer above the hardened one.
- **L-03**: backend emits `subject_alt_names` (`internal/bootstrap/certificate_provider.go:31`); `ui/src/lib/models.ts:41` declares `sans`; `ui/src/mocks/fixtures.ts` uses `sans` throughout. `uri_sans` matches by luck, so SPIFFE URIs render while DNS SANs don't.
- **L-05**: `docs/SESSION_STATUS.md:64` (pre-fix) vs `internal/bootstrap/handlers_meta.go:20,25`; nginx.conf proxies `/healthz` only — `/readyz` falls through to the SPA on :3000 (G-9 nginx ticket).

## Analysis queue (explicit asks for the next improvement pass)

1. Check candidates: L-01 (conditional-job must-run counterpart), L-03 (fixture-from-contract lint/codegen), L-04 (decisions-vs-code challenger pass).
2. Upstream PR candidates to bpm-opencode-experts: L-01 (CI-review checklist), L-02 (release-mode re-status step), L-05 (handoff verify-command rule).
3. Product features carrying a lesson: OpenAPI regeneration + CI validation (G-5) would have caught L-03's class mechanically (contract-first fixtures).
