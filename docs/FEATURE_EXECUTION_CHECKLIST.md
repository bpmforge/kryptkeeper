# Feature Execution Checklist

## Purpose
Break the v1 UI improvement effort into an execution order that can be built safely.

## Wave 1 — stabilize and prepare
- [ ] Extract shared DB provider initialization
- [ ] Add typed domain errors and consistent response mapping
- [ ] Add startup validation reporting
- [ ] Add failure-path tests for auth, list, and action endpoints
- [ ] Create shared UI states: loading, empty, error, retry

## Wave 2 — make inventory usable
- [ ] Build dashboard risk rail
- [ ] Make dashboard metrics clickable to filtered views
- [ ] Add certificate filters and sorting
- [ ] Add discovery filters and sorting
- [ ] Add alerts center with pending/failure emphasis
- [ ] Improve CA list visual status cues

## Wave 3 — add detail screens
- [ ] Add certificate detail page
- [ ] Add discovery endpoint detail page
- [ ] Add notification delivery detail or center view
- [ ] Add CA detail page
- [ ] Add audit/history page or panel
- [ ] Add action dialog pattern used across pages

## Wave 4 — add actions
- [ ] Add renew/revoke/import flows
- [ ] Add scan queue management flows
- [ ] Add retry/ack/test delivery flows
- [ ] Add CA activate/suspend/update flows
- [ ] Ensure all actions update the UI without refresh hacks

## Wave 5 — enterprise controls
- [ ] Add role-aware navigation/action visibility
- [ ] Add bulk selection and bulk actions
- [ ] Add audit evidence export views
- [ ] Add global search across core inventory objects

## Wave 6 — harden
- [ ] Add observability for key workflows
- [ ] Add accessibility checks
- [ ] Add performance checks on large inventory pages
- [ ] Add regression coverage for critical flows

## Acceptance criteria
- User can identify urgent work from the dashboard.
- User can search and filter inventory.
- User can inspect a record before acting.
- User can perform routine operations from the UI.
- User can verify outcomes in history/audit.

## Recommended sequencing
1. Dashboard triage
2. Certificates inventory/detail
3. Discovery inventory/detail
4. Alerts/notifications center
5. CA detail
6. Audit/history
7. Bulk actions

## Dependency notes
- UI work depends on stable API shapes.
- Additive backend endpoints should be implemented before UI action buttons.
- Shared components should be built before page-by-page duplication.
