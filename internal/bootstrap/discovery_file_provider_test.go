// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"strings"
	"testing"
)

// S-70: an environment with nothing discovered must say so everywhere. The
// file provider used to hard-code three endpoints and three scan jobs into
// its lists while GetSummary reported env-default zeros — one page, two
// sources, contradictory answers.
func TestFileDiscoveryProviderIsEmptyWithoutDemoSeeds(t *testing.T) {
	t.Setenv(discoveryDemoSeedsEnv, "")
	t.Setenv("APP_DISCOVERY_DISCOVERED_ENDPOINTS", "")
	t.Setenv("APP_DISCOVERY_RISKY_ENDPOINTS", "")
	t.Setenv("APP_DISCOVERY_ACTIVE_SCAN_JOBS", "")

	p := newFileDiscoveryProvider()

	endpoints, err := p.ListEndpoints(context.Background(), DiscoveryEndpointQuery{Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if endpoints.Total != 0 || len(endpoints.Endpoints) != 0 {
		t.Fatalf("expected no endpoints without demo seeds, got %+v", endpoints)
	}

	jobs, err := p.ListScanJobs(context.Background(), DiscoveryScanJobQuery{Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if jobs.Total != 0 || len(jobs.ScanJobs) != 0 {
		t.Fatalf("expected no scan jobs without demo seeds, got %+v", jobs)
	}

	summary, err := p.GetSummary(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if summary.DiscoveredEndpoints != 0 || summary.RiskyEndpoints != 0 || summary.ActiveScanJobs != 0 {
		t.Fatalf("expected zero summary without demo seeds, got %+v", summary)
	}
}

// With demo seeds opted in, the counters must agree with what the lists
// return — the seeds exist to demo the page, not to contradict it.
func TestFileDiscoveryProviderDemoSeedsAgreeWithSummary(t *testing.T) {
	t.Setenv(discoveryDemoSeedsEnv, "true")
	t.Setenv("APP_DISCOVERY_DISCOVERED_ENDPOINTS", "")
	t.Setenv("APP_DISCOVERY_RISKY_ENDPOINTS", "")
	t.Setenv("APP_DISCOVERY_ACTIVE_SCAN_JOBS", "")

	p := newFileDiscoveryProvider()

	endpoints, err := p.ListEndpoints(context.Background(), DiscoveryEndpointQuery{Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	risky, err := p.ListEndpoints(context.Background(), DiscoveryEndpointQuery{RiskyOnly: true, Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	jobs, err := p.ListScanJobs(context.Background(), DiscoveryScanJobQuery{Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	active := 0
	for _, job := range jobs.ScanJobs {
		if job.Status == "queued" || job.Status == "running" {
			active++
		}
	}

	summary, err := p.GetSummary(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if summary.DiscoveredEndpoints != endpoints.Total {
		t.Errorf("summary discovered %d != listed %d", summary.DiscoveredEndpoints, endpoints.Total)
	}
	if summary.RiskyEndpoints != risky.Total {
		t.Errorf("summary risky %d != listed risky %d", summary.RiskyEndpoints, risky.Total)
	}
	if summary.ActiveScanJobs != active {
		t.Errorf("summary active %d != listed active %d", summary.ActiveScanJobs, active)
	}
}

// Seeded hostnames must carry a visible demo mark so a UI showing them cannot
// be mistaken for real inventory.
func TestFileDiscoveryProviderDemoSeedsAreMarked(t *testing.T) {
	t.Setenv(discoveryDemoSeedsEnv, "true")

	p := newFileDiscoveryProvider()
	endpoints, err := p.ListEndpoints(context.Background(), DiscoveryEndpointQuery{Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(endpoints.Endpoints) == 0 {
		t.Fatal("expected demo seeds to be present when opted in")
	}
	for _, ep := range endpoints.Endpoints {
		if !strings.HasPrefix(ep.Hostname, "demo-") {
			t.Errorf("seeded endpoint %q is not marked as demo data", ep.Hostname)
		}
	}
}
