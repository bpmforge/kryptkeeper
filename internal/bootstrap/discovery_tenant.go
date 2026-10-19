// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"errors"
)

// Discovery rows (scan jobs, endpoints) carry a tenant. The scope travels in
// the context rather than in every DiscoveryProvider signature so the
// dashboard, search and the mesh scheduler keep calling the same methods:
// a context with no scope is the internal, unfiltered caller (and stamps the
// default tenant on anything it writes).
//
// Endpoints are one row per (tenant, host, port, sni): when two tenants scan
// the same address each keeps its own row, so tenant B's scan can never update
// or read tenant A's findings.

type discoveryScopeKey struct{}

type discoveryScope struct {
	tenant string // canonical storage value: "" is DefaultTenant
	filter bool   // restrict reads/mutations to tenant
}

// errDiscoveryScanJobNotFound is returned when a scan job does not exist or
// belongs to a tenant the caller cannot see; the handler answers 404 for both
// so job IDs of other tenants are not confirmable.
var errDiscoveryScanJobNotFound = errors.New("scan job not found")

// discoveryTenantValue maps a tenant name to its stored form. Migration 000083
// defines the empty string as DefaultTenant so existing rows need no backfill.
func discoveryTenantValue(tenant string) string {
	if tenant == DefaultTenant {
		return ""
	}
	return tenant
}

// withDiscoveryScope tags ctx with the principal's tenant. Reads are filtered
// unless the principal bypasses tenant filtering (multi-tenancy off, or an
// unscoped super-admin).
func withDiscoveryScope(ctx context.Context, pd AuthPrincipal) context.Context {
	return context.WithValue(ctx, discoveryScopeKey{}, discoveryScope{
		tenant: discoveryTenantValue(pd.Tenant),
		filter: !tenantBypass(pd),
	})
}

// withDiscoveryTenant tags a background context with the tenant that owns a
// running scan so its persisted endpoints inherit it.
func withDiscoveryTenant(ctx context.Context, storedTenant string) context.Context {
	return context.WithValue(ctx, discoveryScopeKey{}, discoveryScope{tenant: storedTenant})
}

func discoveryScopeFrom(ctx context.Context) discoveryScope {
	sc, _ := ctx.Value(discoveryScopeKey{}).(discoveryScope)
	return sc
}

// discoveryStampTenant is the tenant to write on new scan jobs and endpoints.
func discoveryStampTenant(ctx context.Context) string { return discoveryScopeFrom(ctx).tenant }

// discoveryFilterTenant reports the tenant reads must be restricted to.
func discoveryFilterTenant(ctx context.Context) (tenant string, filter bool) {
	sc := discoveryScopeFrom(ctx)
	return sc.tenant, sc.filter
}

// ensureDiscoveryTenantIndex replaces the tenant-blind endpoint identity
// indexes with the per-tenant one. Idempotent; shared by both dialects and by
// migration 000083.
func ensureDiscoveryTenantIndex(ctx context.Context, db *sql.DB) error {
	for _, stmt := range []string{
		"DROP INDEX IF EXISTS idx_endpoint_unique_identity",
		"DROP INDEX IF EXISTS idx_endpoint_unique_network_identity",
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_endpoint_unique_identity_tenant ON endpoints(tenant, ip_address, port, sni_name)",
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

// discoverySummaryScope holds the tenant predicates the summary and findings
// queries splice in. Unscoped callers get "1=1" and no args, so one SQL text
// serves both cases.
type discoverySummaryScope struct {
	endpoints string // over `endpoints e`
	links     string // over `certificate_endpoints ce`
	jobs      string // over `scan_jobs`
	args      []any
}

// newDiscoverySummaryScope builds the predicates around a single numbered
// placeholder (?1 / $1) that may be reused in every sub-select.
func newDiscoverySummaryScope(ctx context.Context, placeholder string) discoverySummaryScope {
	tenant, filter := discoveryFilterTenant(ctx)
	if !filter {
		return discoverySummaryScope{endpoints: "1=1", links: "1=1", jobs: "1=1"}
	}
	return discoverySummaryScope{
		endpoints: "e.tenant = " + placeholder,
		links:     "ce.endpoint_id IN (SELECT id FROM endpoints WHERE tenant = " + placeholder + ")",
		jobs:      "tenant = " + placeholder,
		args:      []any{tenant},
	}
}

// requireDiscoveryJobVisible fails with errDiscoveryScanJobNotFound when the
// caller is tenant-filtered and the job is not theirs (or does not exist).
// idPH/tenantPH are the dialect's placeholders for the two arguments.
func requireDiscoveryJobVisible(ctx context.Context, db *sql.DB, jobID, idPH, tenantPH string) error {
	tenant, filter := discoveryFilterTenant(ctx)
	if !filter {
		return nil
	}
	var one int
	err := db.QueryRowContext(ctx, "SELECT 1 FROM scan_jobs WHERE id = "+idPH+" AND tenant = "+tenantPH, jobID, tenant).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return errDiscoveryScanJobNotFound
	}
	return err
}
