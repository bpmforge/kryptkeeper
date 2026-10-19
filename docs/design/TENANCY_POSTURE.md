# Tenancy — Current Enforcement Posture

**Date:** 2026-10-16. **Status:** tenant isolation is **enforced, verified by the tenant-idor
suite** (`bash scripts/test/run.sh --suite tenant-idor`, 0 cross-tenant leaks on SQLite and
PostgreSQL). The 21 leaks found in the v0.9.3 live validation are closed in v0.10 (W21-01..03,
W22-01, W22-02). The experimental start-up gate was lifted by owner decision on 2026-10-16
(`docs/release/MULTI_TENANCY_GATE_DECISION.md`).

## Operating it

`MULTI_TENANCY` is off by default; when off, every principal is super-admin in the `default`
tenant and nothing below applies. With `MULTI_TENANCY` on, the hub starts normally and logs a
NOTICE pointing at this document. `KRYPTKEEPER_MULTI_TENANCY_GATE=enforce` restores the v0.9
refusal (rollback): the hub then refuses to start unless
`KRYPTKEEPER_MULTI_TENANCY_EXPERIMENTAL=accept-risk` is also set (exact, case-sensitive).
Instance-wide settings (runtime config, delivery plugins, ceremonies, SCEP challenges, AD sync,
SoD constraints, global custom roles, keystore operations on unmapped keys) are platform
super-admin only while multi-tenancy is on.

## What IS enforced today

Verified against the code (`internal/bootstrap`):

- **Tenant-scoped CA, certificate, template, approval and pending-action reads/writes.**
  Visibility helpers (`caVisibleToTenant`, `templateVisibleToTenant`, `filter*ByTenant` in
  `handlers_tenants.go`) are applied by the list handlers and by the single-resource and
  mutating paths in `handlers_cas.go`, `handlers_certificates.go`, `handlers_templates.go`,
  `handlers_approvals.go`, `handlers_targets.go` and `handlers_pending_actions.go`.
  Reports and the dashboard are scoped via `report_tenant_scope.go`.
- **`X-Tenant` mismatch is rejected.** For a non-bootstrap principal, an `X-Tenant` naming a
  tenant other than the one bound to the identity is denied (`errTenantMismatch`,
  `resolvePrincipalTenancy` in `auth.go`).
- **Identity-bound tenant.** API keys carry their tenant (set at creation); JWT/OIDC principals
  take it from the claim named by `APP_AUTH_TENANT_CLAIM`. A principal without one resolves to
  `default`.
- **`X-Tenant` is a view-as selector only for the bootstrap/root super-admin.**
- **Audit events carry the resolved principal's tenant** (`audit_events.go`); `GET /audit`
  returns only the caller's tenant for non-super-admins.

## Closed in v0.10 and remaining limits

Every gap listed for v0.9 (A01-001, A01-002, A01-004..007, A01S-3, A01S-6, OWASP-002) and every
leak L-01..L-21 in `docs/release/TENANT_ISOLATION_VALIDATION_v0.9.3.md` is fixed and covered by
a `TestLeakL*` regression test in `internal/bootstrap` plus the tenant-idor suite. Audit rows take
their tenant from the resolved principal, never from `X-Tenant`.

Remaining limits, by design or tracked:

- One SSH CA key for the whole hub (L-22, design).
- The tenant-idor suite cannot see a write that changes instance-global state without naming
  another tenant's data; the super-admin gate on global settings (L-08) is proven by unit tests.
- Keystore keys not backing a CA, SCIM/OIDC-provisioned users (land in `default`) and legacy
  tenant-less credentials (belong to `default`) are documented behaviours, not leaks.
- Agent-reported endpoints (`agent_endpoints`) carry no tenant; they are reachable only through
  a tenant-authorized target.

## History

The 2026-07-16 snapshot (W0-04) described header-trusted, read-only scoping; identity-bound
tenancy (W3-01) and write-path checks have since landed, but the audit above showed the
remaining gaps. `docs/v2.2_MULTI_TENANCY_SCOPE.md` describes the target design, not the current
implementation.
