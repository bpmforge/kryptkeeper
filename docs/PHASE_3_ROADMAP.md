# Phase 3 Roadmap

## Goal
Prepare the product design so the UI becomes useful for small PKI teams now and scalable later.

## What we already have
- UX principles and spec
- UX backlog
- feature context
- impact analysis
- implementation plan

## Immediate next work

### 1. UI architecture decisions
- Keep the current React app structure.
- Add shared list/detail/action page patterns.
- Add reusable state handling for loading, empty, error, and success.

### 2. API support for the UI
- Confirm detail endpoints for core inventory objects.
- Confirm mutation endpoints for actions the UI needs.
- Keep responses consistent and additive.

### 3. Information architecture
- Dashboard
- Certificates
- CAs
- Discovery
- Alerts / notifications
- Audit/history

### 4. Workflow design
- Triage urgent items
- Inspect inventory
- Take action
- Confirm outcome
- Review audit trail

## Suggested delivery order
1. Dashboard triage improvements
2. Certificates list/detail
3. Discovery list/detail
4. Alerts/notifications center
5. CA management detail pages
6. Audit/history views

## What to avoid
- Do not add visual polish before workflows exist.
- Do not add bulk actions before single-item detail/action flows.
- Do not introduce complex integrations yet.

## Success criteria
- Users understand what to do next.
- Users can work faster with fewer clicks.
- The UI can handle growing inventory without becoming confusing.
