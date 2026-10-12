# Feature Impact Analysis

## Scope
This feature touches the operational UI, inventory/list endpoints, detail/action workflows, and audit/history paths.

## Impact summary

### Frontend
Affected files:
- `ui/src/App.tsx`
- `ui/src/lib/api.ts`
- `ui/src/pages/Dashboard.tsx`
- `ui/src/pages/Certificates.tsx`
- `ui/src/pages/CAs.tsx`
- `ui/src/pages/Discovery.tsx`
- `ui/src/pages/Alerts.tsx`
- new shared components for search/filter/detail/action states
- new detail pages/routes for certificate, discovery endpoint, notification, CA, and audit views

### Backend
Affected files:
- `internal/bootstrap/handlers_dashboard.go`
- `internal/bootstrap/handlers_certificates.go`
- `internal/bootstrap/handlers_cas.go`
- `internal/bootstrap/handlers_discovery.go`
- `internal/bootstrap/handlers_notifications.go`
- `internal/bootstrap/handlers_audit.go`
- `internal/bootstrap/handlers_auth.go`
- `internal/bootstrap/handlers_protocols.go`
- `internal/bootstrap/dashboard_action_db_provider.go`
- `internal/bootstrap/certs_summary_db_provider.go`
- `internal/bootstrap/discovery_db_provider.go`
- `internal/bootstrap/notification_db_provider.go`
- `internal/bootstrap/audit_db_provider.go`
- `internal/bootstrap/handlers.go`
- `internal/bootstrap/server.go`

### Data stores / models
Likely impacted tables/data domains:
- `certificates`
- `certificate_endpoints`
- `endpoints`
- `scan_jobs`
- `notification_deliveries`
- `audit_log`
- CA/template provider records (file-backed or DB-backed depending on deployment)

### Tests
Affected/expanded tests:
- `internal/bootstrap/*_test.go` around list, detail, action, and error paths
- UI tests for new routes/components
- integration tests for inventory-to-action flows

## Current endpoint coverage
Already present and likely reused:
- `GET /api/v1/dashboard/summary`
- `GET /api/v1/dashboard/actions`
- `GET /api/v1/dashboard/actions/history`
- `POST /api/v1/dashboard/actions/ack`
- `POST /api/v1/dashboard/actions/resolve`
- `GET /api/v1/certificates`
- `GET /api/v1/certificates/:fingerprint`
- `GET /api/v1/certificates/:fingerprint/chain`
- `POST /api/v1/certificates`
- `POST /api/v1/certificates/import`
- `POST /api/v1/certificates/:fingerprint/revoke`
- `GET /api/v1/cas`
- `GET /api/v1/cas/:id`
- `PATCH /api/v1/cas/:id`
- `DELETE /api/v1/cas/:id`
- `POST /api/v1/cas/:id/suspend`
- `POST /api/v1/cas/:id/activate`
- `GET /api/v1/discovery/summary`
- `GET /api/v1/discovery/endpoints`
- `GET /api/v1/discovery/scan-jobs`
- `POST /api/v1/discovery/scans`
- `POST /api/v1/discovery/scan-jobs/cancel`
- `POST /api/v1/discovery/scan-jobs/requeue`
- `GET /api/v1/notifications/summary`
- `GET /api/v1/notifications/deliveries`
- `POST /api/v1/notifications/test-delivery`
- `POST /api/v1/notifications/deliveries/retry`
- `POST /api/v1/notifications/deliveries/ack`
- `GET /api/v1/audit`
- `GET /api/v1/protocols/status`

## Gaps to close for the feature

### Frontend gaps
- No detail routes for core inventory objects
- No shared filter/search/sort toolbar
- No bulk actions UI
- No action confirmation workflow
- No audit/history view in the UI

### Backend gaps
- Need consistent detail payloads for drill-down screens
- Need additive endpoints for bulk operations if required
- Need more uniform error typing and response mapping
- Need shared pagination/filter conventions across domains

### Product gaps
- Dashboard is informative but not action-oriented enough
- Discovery and notification flows are not yet first-class operational workflows
- Users cannot yet manage inventory at scale from the UI alone

## Risk assessment

| Risk | Blast radius | Notes |
|---|---|---|
| Changing core handlers | High | Affects auth, audit, and user-facing operational screens |
| Adding detail routes | Medium | Mostly additive, but needs consistent UI patterns |
| Adding bulk actions | Medium | Can introduce authorization and audit complexity |
| Refactoring DB providers | Medium | Repeated code now, but many call sites |
| UI state overhaul | Medium | Can be done incrementally if shared components are introduced |

## Recommended implementation slices
1. Dashboard triage and ranked actions
2. Certificates inventory/detail/action flow
3. Discovery inventory/detail/action flow
4. Notifications/alerts delivery center
5. CA management detail flow
6. Audit/history surfaces
7. Bulk actions and enterprise controls

## Dependency order
1. Confirm UX spec and backlog
2. Stabilize shared API patterns
3. Add/expand backend detail endpoints where missing
4. Build frontend list/detail pages
5. Add actions and audit visibility
6. Add bulk/role-based enterprise features

## Implementation note
The UX work already exists and should be treated as a required input, not a separate workstream.
