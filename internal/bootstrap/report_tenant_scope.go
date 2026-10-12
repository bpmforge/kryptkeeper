// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"net/http"
)

// W2-03/D-102 (R-B3): report and dashboard endpoints previously discarded
// principal tenancy entirely (authenticating via AuthenticatePrincipal, which
// drops the resolved AuthPrincipal down to a bare ID string) and aggregated
// over the whole fleet regardless of caller. This file gives every api-lane
// report family one of two treatments, per D-102's adopted either/or:
//
//   - Filterable families (built from per-item CertificateItem/CAListItem/
//     AuditEntry lists that already carry a tenant-mappable ID) are scoped
//     via reportScopeCertificates/reportScopeCAs/reportScopeAuditEntries,
//     reusing the same store-backed CA/template tenant mapping as every other
//     tenant-filtered list in the codebase (filterCertificatesByTenant et al.
//     in handlers_tenants.go).
//   - Genuinely aggregate families — built from fleet-wide summary/snapshot
//     stores that have no per-tenant breakdown at all (dashboard summaries,
//     posture-trend snapshots, compliance evidence-pack schedules, the PQC
//     countdown's trend/wave series) — are gated by
//     denyAggregateReportForTenantScoped instead of silently mixing tenants'
//     data into one number. Retrofitting real per-tenant aggregation into
//     those stores is a separate, larger change (new query shapes on
//     certs_summary/discovery/notification/posture_snapshot/evidence_schedule
//     stores), out of this ticket's write_scope.
//
// Both treatments are no-ops when multi-tenancy is off or the caller is an
// unscoped super-admin (tenantBypass).

// reportScopeCertificates filters a certificate list to those visible to pd,
// via each item's issuing CA's tenant mapping.
func reportScopeCertificates(ctx context.Context, pd AuthPrincipal, items []CertificateItem) []CertificateItem {
	return filterCertificatesByTenant(ctx, activeTenantStore, pd, items)
}

// reportScopeCAs filters a CA list to those visible to pd.
func reportScopeCAs(ctx context.Context, pd AuthPrincipal, items []CAListItem) []CAListItem {
	return filterCAsByTenant(ctx, activeTenantStore, pd, items)
}

// reportScopeAuditEntries filters an audit entry list to those visible to pd,
// using each entry's own stamped Tenant (W2-04) directly — no store lookup,
// same shape as filterPendingActionsByTenant.
func reportScopeAuditEntries(pd AuthPrincipal, items []AuditEntry) []AuditEntry {
	if tenantBypass(pd) {
		return items
	}
	out := make([]AuditEntry, 0, len(items))
	for _, item := range items {
		t := item.Tenant
		if t == "" {
			t = DefaultTenant
		}
		if t == pd.Tenant {
			out = append(out, item)
		}
	}
	return out
}

// denyAggregateReportForTenantScoped rejects a tenant-scoped principal's
// request to a fleet-wide aggregate report/dashboard endpoint that has no
// per-tenant breakdown (D-102/R-B3's aggregate-super-admin-only branch). It
// writes a 403 and returns true when the request was denied; the caller
// should return immediately. A no-op (returns false, writes nothing) when
// tenancy is off or the caller is an unscoped super-admin.
func denyAggregateReportForTenantScoped(w http.ResponseWriter, pd AuthPrincipal) bool {
	if tenantBypass(pd) {
		return false
	}
	writeForbidden(w, "this report aggregates fleet-wide data with no per-tenant breakdown and is restricted to super-admins (D-102)")
	return true
}
