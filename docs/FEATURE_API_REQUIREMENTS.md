# Feature API Requirements

## Goal
Support the UI improvements with consistent, additive API changes.

## Existing endpoints that can be reused
- dashboard summary/actions/history/ack/resolve
- certificates list/detail/chain/import/revoke
- CAs list/detail/update/suspend/activate/delete
- discovery summary/endpoints/scan-jobs/scans/cancel/requeue
- notifications summary/deliveries/test/retry/ack
- audit list
- protocols status/readiness/conformance

## API gaps for the UI plan

### Certificates
Potential needs:
- more explicit list filters for team, CA, status, expiry, grade, risk
- clearer detail payload for certificate history and dependent endpoints
- dedicated renewal action endpoint if renew isn’t already exposed in UI-friendly form

### Discovery
Potential needs:
- endpoint detail payload
- scan job detail payload
- stronger filtered list metadata for large inventories

### Notifications
Potential needs:
- delivery detail payload
- action payloads that return consistent result objects for retry/ack/test

### CAs
Potential needs:
- CA detail payload with issuance/trust context
- clear update response for UI state refresh

### Audit
Potential needs:
- resource-oriented history payloads
- filters that map directly to UI search controls

## API design rules
- Keep responses additive.
- Use consistent `data` and `meta` envelopes.
- Keep errors typed and predictable.
- Support cursor-based pagination where lists can grow large.
- Prefer one-purpose endpoints for UI actions.

## Backend changes likely needed
1. normalize list response shape across domains
2. add or refine detail endpoints
3. add missing action endpoints for UI interactions
4. standardize validation and error mapping
5. support filter/search params used by the new screens

## Minimal API contract for v1 UI
The UI should be able to:
- load dashboard triage data
- search/filter certificates
- open certificate detail
- inspect discovery endpoints and scan jobs
- inspect and act on deliveries
- inspect CA detail and state
- review audit history

## Non-goals for v1
- external integrations
- advanced automation orchestration
- multi-region topology
- large-scale queue processing changes

## Acceptance criteria
- Every screen has the data it needs without client-side hacks.
- Actions can complete without page refresh hacks.
- List filters map cleanly to backend query parameters.
- Detail pages can load from stable identifiers.
