# Sprint 1 Plan

## Objective
Stabilize the platform and lay the UI foundation for the v1 PKI operations workflow.

## Sprint goal
By the end of Sprint 1, the team should have:
- safer backend startup/error handling
- shared UI states for loading/empty/error/retry
- a risk-first dashboard entry point
- backend/UI failure-path coverage for the most important flows

## Scope

### In scope
- shared DB provider helper refactor
- typed errors / standardized response mapping
- startup validation reporting
- shared UI state components
- dashboard risk rail and action-first summary
- failure-path tests for critical backend handlers
- dashboard UI tests

### Out of scope
- detail pages
- bulk actions
- CA/discovery/alert deep workflows
- external integrations
- design polish beyond foundational layout changes

## Priority order

### Day 1-2: backend stabilization
1. **B1.1** Create shared DB provider factory/helper
2. **B1.2** Replace string-matched errors with typed domain errors
3. **B1.3** Add startup validation report before serving traffic
4. **B1.4** Standardize JSON error response helpers

### Day 2-3: backend tests
5. **T1.1** Add startup failure-path tests
6. **T1.2** Add auth failure-path tests
7. **T1.3** Add list/action error-path tests for core handlers

### Day 3-4: UI foundation
8. **F2.1** Add shared loading/empty/error/retry state components
9. **F2.2** Add dashboard risk command rail
10. **F2.3** Make dashboard metrics clickable to filtered views

### Day 4-5: dashboard tests and validation
11. **T2.1** Add UI tests for dashboard summary render states
12. **T2.2** Add UI tests for certificate/discovery filter behavior (basic groundwork only)

## Task breakdown

### B1.1 Shared DB provider helper
Purpose: remove duplicated open/ping/mode boilerplate.

Acceptance:
- one helper handles DB open/validate
- providers use the helper consistently
- tests still pass

### B1.2 Typed errors
Purpose: make backend failure responses predictable.

Acceptance:
- auth/domain failures map to explicit error types
- handlers no longer rely on string comparisons

### B1.3 Startup validation report
Purpose: fail fast and explain configuration issues.

Acceptance:
- app reports startup problems clearly before serving traffic

### B1.4 JSON error helpers
Purpose: unify error envelopes.

Acceptance:
- common responses for bad request, unauthorized, forbidden, not found, conflict, unavailable

### T1.1 Startup failure-path tests
Purpose: prevent regressions in config/bootstrap.

Acceptance:
- invalid DB mode/DSN scenarios covered

### T1.2 Auth failure-path tests
Purpose: ensure auth is safe and predictable.

Acceptance:
- invalid credentials, inactive account, unauthorized token, rate limit cases covered

### T1.3 Handler error-path tests
Purpose: lock down core list/action failure behavior.

Acceptance:
- list/action handlers return the expected error codes and envelopes

### F2.1 Shared UI state components
Purpose: eliminate repeated loading/error UI.

Acceptance:
- reusable components exist for loading, empty, error, retry

### F2.2 Dashboard risk rail
Purpose: make the first screen task-oriented.

Acceptance:
- dashboard shows urgent work first
- metrics point into relevant areas

### F2.3 Clickable dashboard metrics
Purpose: reduce steps to action.

Acceptance:
- clicking summary cards takes users to filtered inventory views

### T2.1 Dashboard UI tests
Purpose: protect the new entry point.

Acceptance:
- loading, error, and action-rail states are covered

### T2.2 Groundwork tests for filters
Purpose: prepare for next sprint list/detail work.

Acceptance:
- shared state and filter primitives are test-ready

## Dependencies
- Typed errors should land before response mapping tests.
- Shared UI states should land before dashboard refactor work.
- Dashboard click targets should be confirmed before UI tests.

## Suggested owners
- Backend refactor: Go engineer
- UI foundation: React engineer
- Tests: test engineer / backend engineer
- Validation: SDLC lead

## Definition of done
Sprint 1 is done when the backend is safer to change, the dashboard is action-oriented, and the critical failure paths are covered by tests.
