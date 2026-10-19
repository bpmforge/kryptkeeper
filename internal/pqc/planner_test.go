// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package pqc

import (
	"strings"
	"testing"
	"time"
)

func TestNewPlanner(t *testing.T) {
	deadline := time.Now().Add(365 * 24 * time.Hour)
	p := NewPlanner(deadline)
	if p == nil {
		t.Fatal("expected non-nil planner")
	}
}

func TestGenerateRoadmapEmpty(t *testing.T) {
	p := NewPlanner(time.Now().Add(365 * 24 * time.Hour))
	rm := p.GenerateRoadmap(nil)
	if rm.TotalCerts != 0 {
		t.Errorf("expected 0 total, got %d", rm.TotalCerts)
	}
	if rm.Items == nil {
		t.Error("Items must be an empty slice, not nil: it encodes as JSON null and the UI reads items.length")
	}
}

func TestGenerateRoadmapClassifiesCritical(t *testing.T) {
	p := NewPlanner(time.Now().Add(365 * 24 * time.Hour))
	certs := []CertRecord{
		{
			Fingerprint: "fp-1",
			Algorithm:   "RSA",
			KeySize:     2048,
			ValidUntil:  time.Now().Add(5 * 365 * 24 * time.Hour), // long-lived
		},
	}
	rm := p.GenerateRoadmap(certs)
	if rm.TotalCerts != 1 {
		t.Errorf("expected 1 cert, got %d", rm.TotalCerts)
	}
	// RSA 2048 long-lived cert should be critical or high priority
	if len(rm.Items) == 0 {
		t.Error("expected at least one migration item")
	}
}

func TestGenerateRoadmapClassifiesCAasCritical(t *testing.T) {
	p := NewPlanner(time.Now().Add(4 * 365 * 24 * time.Hour))
	certs := []CertRecord{
		{
			Fingerprint: "ca-fp",
			Algorithm:   "RSA",
			IsCA:        true,
			ValidUntil:  time.Now().Add(10 * 365 * 24 * time.Hour),
		},
	}
	rm := p.GenerateRoadmap(certs)
	if len(rm.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(rm.Items))
	}
	if rm.Items[0].Priority != PriorityCritical {
		t.Errorf("expected Critical for CA cert, got %s", rm.Items[0].Priority)
	}
}

func TestGenerateRoadmapClassifiesLongLivedAsHigh(t *testing.T) {
	p := NewPlanner(time.Now().Add(4 * 365 * 24 * time.Hour))
	certs := []CertRecord{
		{
			Fingerprint: "long-fp",
			Algorithm:   "RSA",
			ValidUntil:  time.Now().Add(2 * 365 * 24 * time.Hour), // > 1 year
		},
	}
	rm := p.GenerateRoadmap(certs)
	if len(rm.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(rm.Items))
	}
	if rm.Items[0].Priority != PriorityHigh {
		t.Errorf("expected High for long-lived cert, got %s", rm.Items[0].Priority)
	}
}

func TestGenerateRoadmapClassifiesAutoRenewableAsLow(t *testing.T) {
	p := NewPlanner(time.Now().Add(4 * 365 * 24 * time.Hour))
	now := time.Now()
	certs := []CertRecord{
		{
			Fingerprint:   "auto-fp",
			Algorithm:     "ECDSA",
			ValidFrom:     now,
			ValidUntil:    now.Add(90 * 24 * time.Hour), // short-lived
			AutoRenewable: true,
		},
	}
	rm := p.GenerateRoadmap(certs)
	if len(rm.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(rm.Items))
	}
	if rm.Items[0].Priority != PriorityLow {
		t.Errorf("expected Low for auto-renewable cert, got %s", rm.Items[0].Priority)
	}
}

func TestGenerateRoadmapClassifiesShortManualAsMedium(t *testing.T) {
	p := NewPlanner(time.Now().Add(4 * 365 * 24 * time.Hour))
	now := time.Now()
	certs := []CertRecord{
		{
			Fingerprint:   "manual-fp",
			Algorithm:     "ECDSA",
			ValidFrom:     now,
			ValidUntil:    now.Add(90 * 24 * time.Hour),
			AutoRenewable: false, // manual renewal
		},
	}
	rm := p.GenerateRoadmap(certs)
	if len(rm.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(rm.Items))
	}
	if rm.Items[0].Priority != PriorityMedium {
		t.Errorf("expected Medium for short manual cert, got %s", rm.Items[0].Priority)
	}
}

func TestGenerateRoadmapCountsMigrationReady(t *testing.T) {
	p := NewPlanner(time.Now().Add(4 * 365 * 24 * time.Hour))
	certs := []CertRecord{
		{Fingerprint: "mr-1", PQCReadiness: "migration_ready"},
		{Fingerprint: "mr-2", PQCReadiness: "migration_ready"},
		{Fingerprint: "vuln", PQCReadiness: "vulnerable"},
	}
	rm := p.GenerateRoadmap(certs)
	if rm.MigrationReady != 2 {
		t.Errorf("expected 2 migration_ready, got %d", rm.MigrationReady)
	}
	if rm.Vulnerable != 1 {
		t.Errorf("expected 1 vulnerable, got %d", rm.Vulnerable)
	}
}

// TestGenerateRoadmapCountsLeafOnly proves G-70/D-104's new
// quantum_safe_leaf_only category is counted distinctly (not silently
// folded into QuantumSafe or Vulnerable) and generates no roadmap item,
// same as full quantum_safe -- re-issuing the same cert's own key again
// wouldn't fix its issuer's classical signature.
func TestGenerateRoadmapCountsLeafOnly(t *testing.T) {
	p := NewPlanner(time.Now().Add(4 * 365 * 24 * time.Hour))
	certs := []CertRecord{
		{Fingerprint: "leaf-only-1", PQCReadiness: "quantum_safe_leaf_only"},
		{Fingerprint: "leaf-only-2", PQCReadiness: "quantum_safe_leaf_only"},
		{Fingerprint: "safe", PQCReadiness: "quantum_safe"},
	}
	rm := p.GenerateRoadmap(certs)
	if rm.QuantumSafeLeafOnly != 2 {
		t.Errorf("expected 2 quantum_safe_leaf_only, got %d", rm.QuantumSafeLeafOnly)
	}
	if rm.QuantumSafe != 1 {
		t.Errorf("expected 1 quantum_safe, got %d", rm.QuantumSafe)
	}
	if rm.Vulnerable != 0 {
		t.Errorf("expected 0 vulnerable, got %d", rm.Vulnerable)
	}
	if len(rm.Items) != 0 {
		t.Errorf("expected 0 roadmap items (nothing actionable for either category), got %d", len(rm.Items))
	}
}

func TestGenerateRoadmapSortsByPriority(t *testing.T) {
	p := NewPlanner(time.Now().Add(4 * 365 * 24 * time.Hour))
	now := time.Now()
	certs := []CertRecord{
		{Fingerprint: "med", Algorithm: "ECDSA", ValidFrom: now, ValidUntil: now.Add(90 * 24 * time.Hour)},
		{Fingerprint: "ca", Algorithm: "RSA", IsCA: true, ValidFrom: now, ValidUntil: now.Add(10 * 365 * 24 * time.Hour)},
		{Fingerprint: "high", Algorithm: "RSA", ValidFrom: now, ValidUntil: now.Add(2 * 365 * 24 * time.Hour)},
	}
	rm := p.GenerateRoadmap(certs)
	if len(rm.Items) != 3 {
		t.Fatalf("expected 3 items, got %d", len(rm.Items))
	}
	// After sorting: Critical(CA) < High < Medium
	if rm.Items[0].Priority != PriorityCritical {
		t.Errorf("first item should be Critical, got %s", rm.Items[0].Priority)
	}
	if rm.Items[1].Priority != PriorityHigh {
		t.Errorf("second item should be High, got %s", rm.Items[1].Priority)
	}
}

func TestPriorityOrder(t *testing.T) {
	cases := []struct {
		p    MigrationPriority
		want int
	}{
		{PriorityCritical, 0},
		{PriorityHigh, 1},
		{PriorityMedium, 2},
		{PriorityLow, 3},
		{"unknown", 4},
	}
	for _, tc := range cases {
		if got := priorityOrder(tc.p); got != tc.want {
			t.Errorf("priorityOrder(%s) = %d, want %d", tc.p, got, tc.want)
		}
	}
}

func TestGenerateRoadmapSkipsQuantumSafe(t *testing.T) {
	p := NewPlanner(time.Now().Add(365 * 24 * time.Hour))
	certs := []CertRecord{
		{
			Fingerprint:  "fp-2",
			Algorithm:    "ML-DSA",
			KeySize:      0,
			ValidUntil:   time.Now().Add(365 * 24 * time.Hour),
			PQCReadiness: "quantum_safe",
		},
	}
	rm := p.GenerateRoadmap(certs)
	if rm.TotalCerts != 1 {
		t.Errorf("expected 1 cert, got %d", rm.TotalCerts)
	}
	for _, item := range rm.Items {
		if item.Fingerprint == "fp-2" && item.Priority == PriorityCritical {
			t.Error("quantum-safe cert should not be critical")
		}
	}
}

func TestGenerateRoadmapClassifiesCodeSigningAsCritical(t *testing.T) {
	now := time.Now().UTC()
	p := NewPlanner(time.Time{})
	roadmap := p.GenerateRoadmap([]CertRecord{
		{
			Fingerprint:   "cs",
			CommonName:    "release-signing",
			Algorithm:     "RSA",
			ValidFrom:     now,
			ValidUntil:    now.Add(180 * 24 * time.Hour), // short-ish, but code-signing
			PQCReadiness:  "vulnerable",
			IsCodeSigning: true,
		},
	})
	if len(roadmap.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(roadmap.Items))
	}
	if roadmap.Items[0].Priority != PriorityCritical {
		t.Errorf("code-signing cert should be critical, got %s", roadmap.Items[0].Priority)
	}
	if !strings.Contains(roadmap.Items[0].Reason, "Code-signing") {
		t.Errorf("expected code-signing reason, got %q", roadmap.Items[0].Reason)
	}
}

func TestGenerateRoadmapFlagsSANSprawl(t *testing.T) {
	now := time.Now().UTC()
	p := NewPlanner(time.Time{})
	roadmap := p.GenerateRoadmap([]CertRecord{
		{
			Fingerprint:  "san",
			CommonName:   "wildcard",
			Algorithm:    "RSA",
			ValidFrom:    now,
			ValidUntil:   now.Add(400 * 24 * time.Hour), // long-lived → high
			PQCReadiness: "vulnerable",
			SANCount:     40,
		},
	})
	if roadmap.Items[0].Priority != PriorityHigh {
		t.Fatalf("expected high, got %s", roadmap.Items[0].Priority)
	}
	if !strings.Contains(roadmap.Items[0].Reason, "SAN exposure") {
		t.Errorf("expected SAN sprawl note, got %q", roadmap.Items[0].Reason)
	}
}

func TestBuildTimelineQuarterBucketing(t *testing.T) {
	deadline := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	p := NewPlanner(deadline)
	now := time.Date(2029, 5, 17, 12, 0, 0, 0, time.UTC) // 2029-Q2
	at := func(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 0, 0, 0, 0, time.UTC) }
	certs := []CertRecord{
		{PQCReadiness: ReadinessVulnerable, ValidUntil: at(2029, 6, 30).Add(23 * time.Hour)},  // Q2 last day
		{PQCReadiness: ReadinessMigrReady, ValidUntil: at(2029, 7, 1)},                        // Q3 first instant
		{PQCReadiness: ReadinessQuantumSafe, ValidUntil: at(2029, 7, 1)},                      // Q3 migrated
		{PQCReadiness: ReadinessVulnerable, ValidUntil: at(2029, 12, 31).Add(23 * time.Hour)}, // Q4, before 2030
		{PQCReadiness: ReadinessVulnerable, ValidUntil: deadline},                             // 2030-Q1, after (boundary)
		{PQCReadiness: ReadinessVulnerable, ValidUntil: at(2031, 1, 1)},                       // beyond range, after
		{PQCReadiness: ReadinessVulnerable, ValidUntil: at(2029, 1, 1)},                       // expired: before only
		{PQCReadiness: ReadinessLeafOnly, ValidUntil: at(2029, 8, 1)},                         // neither
		{PQCReadiness: "not_applicable", ValidUntil: at(2029, 8, 1)},                          // neither
		{PQCReadiness: ReadinessVulnerable},                                                   // no expiry: skipped
	}
	tl := p.buildTimeline(certs, now)
	want := []QuarterBucket{
		{"2029-Q2", 1, 0}, {"2029-Q3", 1, 1}, {"2029-Q4", 1, 0}, {"2030-Q1", 1, 0},
	}
	if len(tl.Quarters) != len(want) {
		t.Fatalf("quarters = %+v", tl.Quarters)
	}
	for i, w := range want {
		if tl.Quarters[i] != w {
			t.Errorf("quarter %d = %+v, want %+v", i, tl.Quarters[i], w)
		}
	}
	if tl.ExpireBefore2030 != 4 || tl.ExpireAfter2030 != 2 {
		t.Errorf("before/after = %d/%d, want 4/2", tl.ExpireBefore2030, tl.ExpireAfter2030)
	}
}

func TestBuildTimelineEmptyInventory(t *testing.T) {
	p := NewPlanner(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	tl := p.buildTimeline(nil, time.Date(2029, 11, 1, 0, 0, 0, 0, time.UTC))
	if len(tl.Quarters) != 2 || tl.Quarters[0].Quarter != "2029-Q4" || tl.Quarters[1].Quarter != "2030-Q1" {
		t.Fatalf("quarters = %+v", tl.Quarters)
	}
	if tl.ExpireBefore2030 != 0 || tl.ExpireAfter2030 != 0 {
		t.Errorf("expected zero split, got %+v", tl)
	}
}

func TestBuildTimelineAfterDeadlineIsEmptyNotNil(t *testing.T) {
	p := NewPlanner(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	tl := p.buildTimeline(nil, time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC))
	if tl.Quarters == nil || len(tl.Quarters) != 0 {
		t.Errorf("want empty non-nil quarters, got %#v", tl.Quarters)
	}
}

func TestGenerateRoadmapIncludesTimeline(t *testing.T) {
	p := NewPlanner(time.Time{})
	rm := p.GenerateRoadmap(nil)
	if rm.Timeline.Quarters == nil {
		t.Error("timeline quarters must be non-nil for JSON []")
	}
}
