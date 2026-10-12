// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"testing"
)

// TestUpsertEndpointLocked_DedupsOnID is the W2-05 regression for the
// in-memory scanner path (APP_DISCOVERY_PROVIDER=scanner): re-scanning the
// same host:port must update the existing entry in place, not accumulate
// duplicate rows — the pre-fix code unconditionally appended on every scan.
func TestUpsertEndpointLocked_DedupsOnID(t *testing.T) {
	p := &scannerDiscoveryProvider{}

	p.mu.Lock()
	p.upsertEndpointLocked(DiscoveryEndpoint{ID: "ep-shop.example.com-443", Hostname: "shop.example.com", Port: 443, RiskScore: 10})
	p.upsertEndpointLocked(DiscoveryEndpoint{ID: "ep-shop.example.com-443", Hostname: "shop.example.com", Port: 443, RiskScore: 90})
	p.upsertEndpointLocked(DiscoveryEndpoint{ID: "ep-shop.example.com-443", Hostname: "shop.example.com", Port: 443, RiskScore: 5})
	p.mu.Unlock()

	if len(p.endpoints) != 1 {
		t.Fatalf("expected exactly 1 endpoint after 3 re-scans of the same host:port, got %d: %+v", len(p.endpoints), p.endpoints)
	}
	if p.endpoints[0].RiskScore != 5 {
		t.Errorf("expected the latest scan's data to win, got risk_score=%d", p.endpoints[0].RiskScore)
	}

	summary, err := p.GetSummary(context.Background())
	if err != nil {
		t.Fatalf("GetSummary: %v", err)
	}
	if summary.DiscoveredEndpoints != 1 {
		t.Errorf("expected GetSummary to reflect the deduped count (1), got %d", summary.DiscoveredEndpoints)
	}
}

// TestUpsertEndpointLocked_DistinctIDsAppend confirms genuinely distinct
// endpoints (different host:port) both persist — dedup must not
// over-collapse.
func TestUpsertEndpointLocked_DistinctIDsAppend(t *testing.T) {
	p := &scannerDiscoveryProvider{}

	p.mu.Lock()
	p.upsertEndpointLocked(DiscoveryEndpoint{ID: "ep-a-443", Hostname: "a.example.com", Port: 443})
	p.upsertEndpointLocked(DiscoveryEndpoint{ID: "ep-b-443", Hostname: "b.example.com", Port: 443})
	p.mu.Unlock()

	if len(p.endpoints) != 2 {
		t.Fatalf("expected 2 distinct endpoints, got %d", len(p.endpoints))
	}
}
