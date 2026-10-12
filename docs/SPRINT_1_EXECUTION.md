# Sprint 1 Execution Checklist

## Purpose
Give the team a day-by-day order for Sprint 1 so implementation starts with the safest, highest-leverage work.

## Day 1 — backend safety foundation

### Tasks
- [ ] Implement shared DB provider helper/factory
- [ ] Replace duplicated open/ping/mode logic in DB-backed providers
- [ ] Add typed domain error types for common startup/auth failures
- [ ] Draft startup validation reporting shape

### Exit criteria
- DB provider code is less duplicated
- startup failure cases have a defined structure

## Day 2 — backend response consistency

### Tasks
- [ ] Standardize JSON error response helpers
- [ ] Refactor handlers to use typed errors instead of string matching
- [ ] Confirm response envelopes for bad request / unauthorized / forbidden / not found / conflict / unavailable

### Exit criteria
- error responses are predictable and consistent

## Day 3 — backend failure-path tests

### Tasks
- [ ] Add startup failure-path tests
- [ ] Add auth failure-path tests
- [ ] Add handler list/action error-path tests

### Exit criteria
- core failure paths are covered by tests

## Day 4 — UI foundations

### Tasks
- [ ] Build shared loading state component
- [ ] Build shared empty state component
- [ ] Build shared error state component
- [ ] Build shared retry/CTA pattern

### Exit criteria
- screens can reuse common states instead of hand-rolling them

## Day 5 — dashboard triage

### Tasks
- [ ] Add risk-first dashboard command rail
- [ ] Make dashboard metrics clickable
- [ ] Add urgent-action ranking block
- [ ] Add action history preview block

### Exit criteria
- dashboard is task-oriented, not just informational

## Day 6 — dashboard UI tests

### Tasks
- [ ] Add tests for loading state
- [ ] Add tests for error state
- [ ] Add tests for urgent action rendering
- [ ] Add tests for clickable metric behavior

### Exit criteria
- dashboard behavior is locked down by tests

## Day 7 — integration review

### Tasks
- [ ] Run full backend test suite
- [ ] Run UI build
- [ ] Review any regressions
- [ ] Adjust plan for Sprint 2 based on findings

### Exit criteria
- sprint ends with green tests and a clean handoff to Sprint 2

## Suggested ticket order
1. DB provider helper
2. typed error helpers
3. startup validation reporting
4. shared UI state components
5. dashboard risk rail
6. backend failure-path tests
7. dashboard UI tests

## First ticket recommendation
**Start with the shared DB provider helper.**

Why:
- it removes repeated startup code
- it reduces the risk of inconsistent provider behavior
- it creates a safe foundation for the rest of Sprint 1

## Definition of done
Sprint 1 is done when the backend is easier to change, the dashboard is immediately more useful, and the core flows are protected by tests.
