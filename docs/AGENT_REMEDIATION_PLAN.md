# Kryptkeeper — Agent Remediation Plan

**Date:** 2026-04-09  
**Purpose:** stabilize orchestration agents before continuing V2/V3 work

## 1. Why this document exists

Recent delegated review tasks failed before execution:

- `Code-Reviewer Task — Review V2 ADCS replacement readiness`
- `Code-Reviewer Task — Review V3 readiness and gaps`

Failure mode:

- `zsh:1: bad pattern: [Review`

This means we have an agent/tooling reliability problem, not just a product gap.
We should fix the agent path before asking it to validate architecture or code.

## 2. Current assessment

### What is working

- Core platform implementation is largely built.
- V2/V3 packages exist and are partially wired.
- SDLC docs capture the intended roadmap.

### What is not working

- Some delegated tasks fail at launch.
- Agent invocation appears to be shell-sensitive.
- We cannot trust review output until the orchestration path is stable.

## 3. Immediate priorities

| Priority | Action | Owner |
|----------|--------|-------|
| P0 | Fix agent invocation escaping / quoting | platform orchestration |
| P0 | Re-run V2/V3 review tasks after fix | SDLC lead |
| P1 | Confirm no other agents share the same failure mode | orchestration |
| P1 | Add a small smoke test for delegated task execution | tooling |
| P2 | Resume feature-gap review for V2 and V3 | reviewers |

## 4. Agent remediation plan

### Step 1 — isolate the failure

- Reproduce the task call with a minimal prompt.
- Confirm whether square brackets, punctuation, or task labels trigger shell globbing.
- Determine whether the issue is in the task wrapper, shell execution, or prompt formatting.

### Step 2 — harden the wrapper

- Quote/escape task metadata before shell execution.
- Avoid passing human-readable labels directly into shell commands.
- Prefer structured args over string interpolation.
- In opencode, avoid bracketed argument hints like `[review-aspects]` in command
  frontmatter; use plain text hints such as `review-aspects` instead.

### Step 3 — add a smoke test

- Create a tiny delegated task that always succeeds.
- Run it in CI or a local harness.
- Fail fast if the wrapper regresses.

### Step 4 — re-enable reviews

- Re-run the V2 readiness review.
- Re-run the V3 readiness review.
- Only then proceed with implementation planning.

## 5. V2 next steps after agents are fixed

1. Confirm all V2 packages are wired into a runnable binary.
2. Identify missing command entry points for XCEP, WSTEP, and AD sync.
3. Verify SOAP/WS-Trust fidelity against real reference traffic.
4. Add Windows E2E runbook and GPO validation docs.
5. Validate whether WS-08 is truly blocked or just undocumented.

## 6. V3 next steps after agents are fixed

1. Decide which V3 features are product-facing vs library-only.
2. Add API endpoints for inventory and audit views.
3. Add dashboard pages for SSH keys, code-signing, cipher audit, and PQC roadmap.
4. Persist generated findings instead of only in-memory analysis.
5. Define collection/scheduling for real data ingestion.

## 7. Recommendation

Do not continue feature expansion until the agent layer can reliably execute delegated work.
The next best move is a short tooling stabilization pass, then a renewed V2/V3 gap review.

## 8. Suggested follow-up order

1. Fix agent quoting/escaping.
2. Add a delegated-task smoke test.
3. Re-run V2 review.
4. Re-run V3 review.
5. Convert the results into a concrete implementation backlog.

## 9. Applied fix

- Updated opencode review command metadata to remove the bracketed hint syntax that
  can trigger zsh globbing errors.

## 10. Smoke test result

- Attempted a minimal `code-reviewer` smoke task after the metadata fix.
- Result: still failed with `zsh:1: bad pattern: [Smoke`.
- Interpretation: the bug is likely in the task-launcher wrapper itself, not only in
  the command hint metadata.
- Next investigation target: the opencode task execution path that formats/launches
  subagent commands.
