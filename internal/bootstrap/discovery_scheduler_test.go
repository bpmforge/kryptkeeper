// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"sync"
	"testing"
	"time"
)

// W5-12: discovery runs on a recurring schedule — proven through the
// provider interface.

type recordingDiscoveryProvider struct {
	DiscoveryProvider
	mu    sync.Mutex
	calls []string // "type|target"
}

func (r *recordingDiscoveryProvider) CreateScan(_ context.Context, scanType, target string, _ []int) (DiscoveryScanCreateResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, scanType+"|"+target)
	return DiscoveryScanCreateResult{ID: "scan-x", Status: "running"}, nil
}

func (r *recordingDiscoveryProvider) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

func TestDiscoverySchedulerFilesScansEveryTick(t *testing.T) {
	rec := &recordingDiscoveryProvider{}
	sched := newDiscoveryScheduler(rec, 20*time.Millisecond,
		[]string{"10.0.0.0/24", "corp.example.com"}, []string{"cloud_acm"})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sched.Start(ctx)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		calls := rec.snapshot()
		// At least two full ticks: 2 network + 1 cloud per tick.
		if len(calls) >= 6 {
			hasNet, hasCloud := false, false
			for _, c := range calls {
				if c == "targeted|10.0.0.0/24" || c == "targeted|corp.example.com" {
					hasNet = true
				}
				if c == "cloud_acm|" {
					hasCloud = true
				}
			}
			if !hasNet || !hasCloud {
				t.Fatalf("scheduler must file both network and cloud scans, got %v", calls)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("scheduler never reached two full ticks, calls: %v", rec.snapshot())
}

func TestDiscoverySchedulerStopsOnContextCancel(t *testing.T) {
	rec := &recordingDiscoveryProvider{}
	sched := newDiscoveryScheduler(rec, 10*time.Millisecond, []string{"10.0.0.1"}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	sched.Start(ctx)
	time.Sleep(50 * time.Millisecond)
	cancel()
	time.Sleep(30 * time.Millisecond)
	before := len(rec.snapshot())
	time.Sleep(60 * time.Millisecond)
	if after := len(rec.snapshot()); after != before {
		t.Fatalf("scheduler kept firing after cancel: %d -> %d", before, after)
	}
}

func TestDiscoverySchedulerFromEnv(t *testing.T) {
	rec := &recordingDiscoveryProvider{}

	t.Setenv("KRYPTKEEPER_DISCOVERY_SCAN_INTERVAL", "")
	if s := NewDiscoverySchedulerFromEnv(rec); s != nil {
		t.Fatal("no interval must mean no scheduler")
	}

	t.Setenv("KRYPTKEEPER_DISCOVERY_SCAN_INTERVAL", "12h")
	t.Setenv("KRYPTKEEPER_DISCOVERY_SCAN_TARGETS", " 10.0.0.0/24 , host.example.com ")
	t.Setenv("KRYPTKEEPER_DISCOVERY_CLOUD_TYPES", "cloud_acm, nonsense, cloud_gcp_cm")
	s := NewDiscoverySchedulerFromEnv(rec)
	if s == nil {
		t.Fatal("configured scheduler must build")
	}
	if len(s.targets) != 2 {
		t.Fatalf("targets: %v", s.targets)
	}
	// Unknown cloud entries are skipped, valid ones kept.
	if len(s.cloudTypes) != 2 || s.cloudTypes[0] != "cloud_acm" || s.cloudTypes[1] != "cloud_gcp_cm" {
		t.Fatalf("cloud types: %v", s.cloudTypes)
	}
	if s.interval != 12*time.Hour {
		t.Fatalf("interval: %v", s.interval)
	}

	t.Setenv("KRYPTKEEPER_DISCOVERY_SCAN_TARGETS", "")
	t.Setenv("KRYPTKEEPER_DISCOVERY_CLOUD_TYPES", "")
	if s := NewDiscoverySchedulerFromEnv(rec); s != nil {
		t.Fatal("interval without targets or cloud types must disable scheduling")
	}
}
