// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"sort"
	"strings"
)

// S-70: demo seeds are opt-in. Unset, the file provider is genuinely empty —
// a fresh environment must not show fabricated endpoints its counters deny.
const discoveryDemoSeedsEnv = "APP_DISCOVERY_DEMO_SEEDS"

type fileDiscoveryProvider struct{}

func newFileDiscoveryProvider() DiscoveryProvider {
	return &fileDiscoveryProvider{}
}

// Demo seeds are the default tenant's; a tenant-filtered caller outside it sees none.
func fileDiscoveryHiddenFrom(ctx context.Context) bool {
	tenant, filter := discoveryFilterTenant(ctx)
	return filter && tenant != ""
}

func (p *fileDiscoveryProvider) GetSummary(ctx context.Context) (DiscoverySummary, error) {
	if fileDiscoveryHiddenFrom(ctx) {
		return DiscoverySummary{}, nil
	}
	// Defaults derive from the same seed slices the list endpoints serve, so
	// the counters and the lists cannot disagree; the env knobs stay as
	// explicit demo overrides.
	endpoints := seedDiscoveryEndpoints()
	risky := 0
	for _, ep := range endpoints {
		if endpointIsRisky(ep) {
			risky++
		}
	}
	active := 0
	for _, job := range seedDiscoveryScanJobs() {
		if job.Status == "queued" || job.Status == "running" {
			active++
		}
	}
	return DiscoverySummary{
		DiscoveredEndpoints: envInt("APP_DISCOVERY_DISCOVERED_ENDPOINTS", len(endpoints)),
		MappedCertificates:  envInt("APP_DISCOVERY_MAPPED_CERTIFICATES", 0),
		RiskyEndpoints:      envInt("APP_DISCOVERY_RISKY_ENDPOINTS", risky),
		ActiveScanJobs:      envInt("APP_DISCOVERY_ACTIVE_SCAN_JOBS", active),
	}, nil
}

func (p *fileDiscoveryProvider) ListEndpoints(ctx context.Context, query DiscoveryEndpointQuery) (DiscoveryEndpointResult, error) {
	endpoints := seedDiscoveryEndpoints()
	if fileDiscoveryHiddenFrom(ctx) {
		endpoints = nil
	}
	filtered := make([]DiscoveryEndpoint, 0, len(endpoints))
	for _, ep := range endpoints {
		if query.Protocol != "" && !strings.EqualFold(ep.Protocol, query.Protocol) {
			continue
		}
		ep.Risky = endpointIsRisky(ep)
		if query.RiskyOnly && !ep.Risky {
			continue
		}
		filtered = append(filtered, ep)
	}

	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].ID < filtered[j].ID
	})

	result := paginate(filtered, query.Limit, query.Cursor, 25, 100)
	return DiscoveryEndpointResult{
		Endpoints:  result.Items,
		Total:      result.Total,
		Limit:      result.Limit,
		NextCursor: result.NextCursor,
		PrevCursor: result.PrevCursor,
	}, nil
}

func (p *fileDiscoveryProvider) ListScanJobs(ctx context.Context, query DiscoveryScanJobQuery) (DiscoveryScanJobResult, error) {
	scanJobs := seedDiscoveryScanJobs()
	if fileDiscoveryHiddenFrom(ctx) {
		scanJobs = nil
	}
	filtered := make([]DiscoveryScanJob, 0, len(scanJobs))
	for _, job := range scanJobs {
		if query.Status != "" && !strings.EqualFold(job.Status, query.Status) {
			continue
		}
		if query.Q != "" && !strings.Contains(strings.ToLower(job.Target), strings.ToLower(query.Q)) {
			continue
		}
		filtered = append(filtered, job)
	}

	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].QueuedAt > filtered[j].QueuedAt
	})

	result := paginate(filtered, query.Limit, query.Cursor, 25, 100)
	return DiscoveryScanJobResult{
		ScanJobs:   result.Items,
		Total:      result.Total,
		Limit:      result.Limit,
		NextCursor: result.NextCursor,
		PrevCursor: result.PrevCursor,
	}, nil
}

// errDiscoveryScanUnsupported: the file provider has no scan runner. It
// used to fabricate a "queued" job it then discarded — a user's first scan
// vanished with a success response. Refusing with directions is honest and
// the UI surfaces this message verbatim.
var errDiscoveryScanUnsupported = errors.New(
	"network scans need the database-backed discovery provider — set discovery.provider to db (Settings → Integrations, or APP_DISCOVERY_PROVIDER=db) and retry")

func (p *fileDiscoveryProvider) CreateScan(_ context.Context, _ string, _ string, _ []int) (DiscoveryScanCreateResult, error) {
	return DiscoveryScanCreateResult{}, errDiscoveryScanUnsupported
}

func (p *fileDiscoveryProvider) CancelScanJob(_ context.Context, _ string, _ string) (DiscoveryScanJobActionResult, error) {
	return DiscoveryScanJobActionResult{}, errDiscoveryScanUnsupported
}

func (p *fileDiscoveryProvider) RequeueScanJob(_ context.Context, _ string, _ string) (DiscoveryScanJobActionResult, error) {
	return DiscoveryScanJobActionResult{}, errDiscoveryScanUnsupported
}

// The demo- hostname prefix is the visible mark: these rows render in the UI
// unchanged, so the data itself must say it is fabricated.
func seedDiscoveryEndpoints() []DiscoveryEndpoint {
	if !envBool(discoveryDemoSeedsEnv) {
		return nil
	}
	return []DiscoveryEndpoint{
		{ID: "ep-risky-1", Hostname: "demo-legacy-gateway.internal", Port: 443, Protocol: "tls", RiskScore: 92, LastSeenAt: "2026-04-07T01:00:00Z"},
		{ID: "ep-safe-1", Hostname: "demo-api.internal", Port: 443, Protocol: "tls", RiskScore: 20, LastSeenAt: "2026-04-07T01:05:00Z"},
		{ID: "ep-web-1", Hostname: "demo-intranet.internal", Port: 80, Protocol: "http", RiskScore: 55, LastSeenAt: "2026-04-07T01:10:00Z"},
	}
}

func seedDiscoveryScanJobs() []DiscoveryScanJob {
	if !envBool(discoveryDemoSeedsEnv) {
		return nil
	}
	return []DiscoveryScanJob{
		{ID: "scan-1700000000000000001", ScanType: "full", Target: "10.0.0.0/24", Status: "running", QueuedAt: "2026-04-08T02:00:00Z"},
		{ID: "scan-1700000000000000000", ScanType: "targeted", Target: "demo-legacy-gateway.internal", Status: "queued", QueuedAt: "2026-04-08T01:00:00Z"},
		{ID: "scan-1699999999999999999", ScanType: "full", Target: "192.168.1.0/24", Status: "completed", QueuedAt: "2026-04-08T00:00:00Z"},
	}
}

type paginatedResult[T any] struct {
	Items      []T
	Total      int
	Limit      int
	NextCursor *int
	PrevCursor *int
}

func paginate[T any](items []T, limit int, cursor int, defaultLimit int, maxLimit int) paginatedResult[T] {
	if limit <= 0 {
		limit = defaultLimit
	}
	if limit > maxLimit {
		limit = maxLimit
	}
	if cursor < 0 {
		cursor = 0
	}

	total := len(items)
	if cursor > total {
		cursor = total
	}
	end := cursor + limit
	if end > total {
		end = total
	}
	page := items[cursor:end]

	var nextCursor *int
	if end < total {
		n := end
		nextCursor = &n
	}
	var prevCursor *int
	if cursor > 0 {
		p := cursor - limit
		if p < 0 {
			p = 0
		}
		prevCursor = &p
	}

	return paginatedResult[T]{
		Items:      page,
		Total:      total,
		Limit:      limit,
		NextCursor: nextCursor,
		PrevCursor: prevCursor,
	}
}
