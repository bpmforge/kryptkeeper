# UX Implementation Backlog

## Goal
Evolve Kryptkeeper from a status dashboard into a workflow-driven PKI operations platform.

## Priority order

### P0 — make the product operational

#### 1. Dashboard → action-first triage
**User value:** answers “what needs attention now?”

Tasks:
- Replace passive summary cards with a ranked risk command rail
- Make each summary metric clickable into a filtered list
- Add action CTAs for review, renew, revoke, acknowledge, retry
- Add clear empty/loading/error states to every dashboard block

Depends on:
- Dashboard summary endpoint
- Certificates, discovery, notifications summary endpoints

Success criteria:
- User can reach the highest-priority item in 1–2 clicks

#### 2. Certificates → searchable inventory + detail view
**User value:** manage large certificate fleets efficiently

Tasks:
- Add search/filter/sort controls (CA, team, expiry, risk, status)
- Add pagination with preserved filters
- Add detail route for a single certificate
- Show chain, ownership, risk, renewal status, and history
- Add renew/revoke/import actions with confirmation

Depends on:
- `GET /api/v1/certificates`
- `GET /api/v1/certificates/:fingerprint`
- `GET /api/v1/certificates/:fingerprint/chain`
- `POST/PUT/DELETE` mutation endpoints

Success criteria:
- Admin can find a cert, inspect it, and act without leaving the page set

#### 3. Discovery → endpoint risk and scan management
**User value:** identify exposed or misconfigured infrastructure

Tasks:
- Add filters by protocol, risk, team, and status
- Add a detail page for endpoint history and mappings
- Add scan job list and queue management
- Add CTA from risky endpoint to remediation action

Depends on:
- `GET /api/v1/discovery/summary`
- `GET /api/v1/discovery/endpoints`
- `GET /api/v1/discovery/scan-jobs`
- scan action endpoints

Success criteria:
- Security ops can move from discovery signal to remediation work quickly

#### 4. Alerts → delivery center
**User value:** make alert automation visible and actionable

Tasks:
- Show pending deliveries, escalations, and failures in one place
- Add acknowledge and retry actions
- Add history views and retry provenance
- Make failure states explain what to do next

Depends on:
- `GET /api/v1/notifications/summary`
- `GET /api/v1/notifications/deliveries`
- action endpoints for ack/retry/test

Success criteria:
- Users can tell whether automation is healthy at a glance

### P1 — support enterprise workflows

#### 5. CA management detail pages
Tasks:
- Add CA detail screen
- Show key storage, status, trust posture, issuance impact
- Add consistent action patterns for maintenance tasks

#### 6. Role-based navigation
Tasks:
- Tailor nav/actions for admin, operator, auditor, app owner
- Hide non-applicable actions
- Surface the most relevant queue first

#### 7. Bulk operations
Tasks:
- Bulk select on certificate and endpoint lists
- Bulk renew/export/acknowledge/requeue
- Confirm high-impact actions before execution

#### 8. Audit evidence surfaces
Tasks:
- Add audit trail links from every actionable object
- Add exportable evidence views for compliance
- Show last actor, last scan, last delivery, last change

### P2 — harden usability and scale

#### 9. Global search
- Search by certificate CN, fingerprint, CA, endpoint hostname, delivery target

#### 10. Empty/error/retry framework
- Shared UI patterns for all data states
- Retry buttons with preserved filters

#### 11. Accessibility and keyboard flow
- Full keyboard navigation across nav, tables, dialogs, and forms
- Visible focus, ARIA where needed, and 44x44 targets

#### 12. Automation transparency
- Scan history, job status, delivery latency, queue backlog, and SLA indicators

## Recommended delivery sequence

### Wave 1
Dashboard triage + certificates list improvements

### Wave 2
Certificate detail + actions + discovery filters

### Wave 3
Alerts center + scan management + CA detail

### Wave 4
Bulk actions + role-based views + audit exports

## Suggested engineering slices

### Frontend
- Shared data-state components
- Search/filter toolbar
- Detail page layout
- Action confirmation dialog
- Empty/error/retry patterns

### Backend
- Detail endpoints
- Mutation endpoints
- Filter/pagination support
- Audit history payloads

### UX/Design
- Screen hierarchy finalization
- Action prioritization rules
- Copy for risk and empty states

## Notes
- Do not add feature depth before list/detail/action flows exist.
- Every new data-heavy screen should ship with loading, loaded, error, and empty states.
