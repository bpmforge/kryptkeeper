# Tenancy — Current Enforcement Posture

**Date:** 2026-10-09. **Status:** multi-tenancy is **EXPERIMENTAL in v0.9**. Tenant isolation is
**not a security boundary** in this release: a tenant admin can act across tenants. The gaps
below are scheduled for **v0.10**. Owner decision 2026-10-09, following the A01 audit
(`docs/security/final-report.md`, `OWASP_A01_FINDINGS_2026-10-09.md`,
`OWASP_A01_SUPPLEMENT_2026-10-09.md`).

## Operating it

`MULTI_TENANCY` is off by default; when off, every principal is super-admin in the `default`
tenant and nothing below applies. With `MULTI_TENANCY` on, the hub **refuses to start** unless
`KRYPTKEEPER_MULTI_TENANCY_EXPERIMENTAL=accept-risk` is also set (exact, case-sensitive). When
acknowledged it logs a WARNING at startup. The UI shows an "Experimental" label on the Tenants
page and the tenant switcher. Do not use it to host mutually untrusted tenants.

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
- **Audit events carry a tenant field** (`auditRequestTenant`, `audit_events.go`), derived from
  the request header, not the caller's identity (OWASP-002, see gaps).

## KNOWN GAPS (scheduled for v0.10)

| Finding | Gap |
|---|---|
| A01-001 | A tenant admin can mint `pki-admin` API keys in any tenant. |
| A01S-3 | A tenant admin can export another tenant's CA private key. |
| A01-002 | Approval actions can be run against other tenants' certificates. |
| A01-004 / A01-005 | Audit, search, CBOM and SSH-certificate lists are not tenant-filtered. Since FG-3 `GET /api/v1/audit` needs the `audit.read` permission (`handlers_audit.go`, `authz_grant.go`), but a holder in one tenant (a tenant `pki-admin` or `auditor`) reads every tenant's rows. |
| A01-006 | A tenant admin can rewrite global configuration, credentials and plugins. |
| A01S-6 | The user directory is shared: a tenant admin can list and delete other tenants' users. |
| A01-007 | Tenant-filtered lists still return the unfiltered `meta.total`. |
| OWASP-002 | Audit rows take their tenant from the raw `X-Tenant` header, not the caller's identity, so a request can file audit rows under another tenant. |
| New (2026-10-15) | `POST /certificates/bulk-revoke` ignores tenant: a tenant admin can revoke another tenant's certificates in bulk (single revoke correctly returns 403). |
| New (2026-10-15) | `POST /cas` accepts a `parent_ca_id` from another tenant (or the default tenant), so a tenant can chain a sub-CA under someone else's root. |
| New (2026-10-15) | Notification rules, connectors, inventory sources, custom roles and discovery are cross-tenant readable and/or writable; `GET /keys` and the key-custody report list every tenant's keys. |

The single-tenant fixes merged since the audit (FG-2 dual control, FG-3 grant checks, FG-4 SSH policy, FG-5
bearer roles, FG-7 sessions) do not add tenant isolation: FG-3 bounds the roles a caller may grant by the
permissions it holds, not by tenant, and the SSH CA key is still one global key. Until FG-6a/6b land in v0.10,
treat every tenant admin as a platform admin.

The live validation of 2026-10-15 on v0.9.3 (`docs/release/TENANT_ISOLATION_VALIDATION_v0.9.3.md`) found 21
cross-tenant leaks (14 state-changing, 3 critical: full cross-tenant takeover). It confirms every gap above,
records which are partially fixed (A01-004, A01-007, A01S-3), and ranks the v0.10 fixes. What does hold:
single-resource reads and writes, `X-Tenant` spoofing (refused), escalation to global admin (refused), and
the dashboard and aggregate reports.

## History

The 2026-07-16 snapshot (W0-04) described header-trusted, read-only scoping; identity-bound
tenancy (W3-01) and write-path checks have since landed, but the audit above showed the
remaining gaps. `docs/v2.2_MULTI_TENANCY_SCOPE.md` describes the target design, not the current
implementation.
