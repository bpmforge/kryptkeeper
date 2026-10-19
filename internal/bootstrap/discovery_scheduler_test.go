// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"path/filepath"
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
	// running, when set, is returned by ListScanJobs for status "running"
	// (W24-04's blocked-scan fake).
	running []DiscoveryScanJob
}

func (r *recordingDiscoveryProvider) ListScanJobs(_ context.Context, q DiscoveryScanJobQuery) (DiscoveryScanJobResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if q.Status != "running" {
		return DiscoveryScanJobResult{}, nil
	}
	return DiscoveryScanJobResult{ScanJobs: append([]DiscoveryScanJob(nil), r.running...)}, nil
}

func (r *recordingDiscoveryProvider) setRunning(jobs ...DiscoveryScanJob) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.running = jobs
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

func countCalls(calls []string, want string) int {
	n := 0
	for _, c := range calls {
		if c == want {
			n++
		}
	}
	return n
}

func TestDiscoverySchedulerSkipsTickWhileJobRunning(t *testing.T) {
	rec := &recordingDiscoveryProvider{}
	rec.setRunning(DiscoveryScanJob{ID: "job-blocked", ScanType: "targeted", Target: "10.0.0.1", Status: "running"})
	sched := newDiscoveryScheduler(rec, 20*time.Millisecond, []string{"10.0.0.1"}, nil)

	for i := 0; i < 3; i++ {
		sched.runOnce(context.Background())
	}
	if got := rec.snapshot(); len(got) != 0 {
		t.Fatalf("a running job must block the tick, got calls %v", got)
	}
	if sched.skipped.Load() < 3 {
		t.Fatalf("skipped = %d, want >= 3", sched.skipped.Load())
	}
	if rows, _ := sched.store.List(context.Background()); !rows["10.0.0.1"].LastRunAt.IsZero() {
		t.Fatal("a skipped tick must not record a run")
	}

	rec.setRunning()
	sched.runOnce(context.Background())
	if n := countCalls(rec.snapshot(), "targeted|10.0.0.1"); n != 1 {
		t.Fatalf("after the job finishes the next tick must queue one scan, got %d", n)
	}
}

func TestDiscoverySchedulerHonoursPerTargetInterval(t *testing.T) {
	rec := &recordingDiscoveryProvider{}
	sched := newDiscoveryScheduler(rec, 20*time.Millisecond, []string{"A", "B"}, nil)
	hour := time.Hour
	if err := sched.store.SetInterval(context.Background(), "A", "targeted", "A", &hour); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sched.Start(ctx)
	time.Sleep(250 * time.Millisecond)
	cancel()
	calls := rec.snapshot()
	if n := countCalls(calls, "targeted|A"); n != 1 {
		t.Fatalf("A (1h override) scans = %d, want exactly 1 (first run): %v", n, calls)
	}
	if n := countCalls(calls, "targeted|B"); n < 3 {
		t.Fatalf("B (global 20ms) scans = %d, want >= 3", n)
	}
}

func TestDiscoverySchedulerGlobalIntervalStillApplies(t *testing.T) {
	rec := &recordingDiscoveryProvider{}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	sched := newDiscoveryScheduler(rec, time.Hour, []string{"10.0.0.1"}, []string{"cloud_acm"})
	sched.tick = time.Minute
	sched.now = func() time.Time { return now }

	sched.runOnce(context.Background()) // never run: due
	now = now.Add(30 * time.Minute)
	sched.runOnce(context.Background()) // inside the global hour: not due
	if got := rec.snapshot(); len(got) != 2 {
		t.Fatalf("want one network + one cloud scan, got %v", got)
	}
	now = now.Add(31 * time.Minute)
	sched.runOnce(context.Background()) // past the hour: due again
	if got := rec.snapshot(); len(got) != 4 {
		t.Fatalf("want a second pair after the global interval, got %v", got)
	}
}

func TestDiscoveryScheduleStore_SetIntervalClearKeepsLastRun(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "sched.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	st := &dbDiscoveryScheduleStore{db: db, ph: sqlitePlaceholder}
	ctx := context.Background()
	if err := st.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	two := 2 * time.Hour
	if err := st.SetInterval(ctx, "10.0.0.0/24", "targeted", "10.0.0.0/24", &two); err != nil {
		t.Fatal(err)
	}
	ran := time.Date(2026, 10, 15, 8, 0, 0, 0, time.UTC)
	if err := st.RecordRun(ctx, "10.0.0.0/24", "targeted", "10.0.0.0/24", "job-1", ran); err != nil {
		t.Fatal(err)
	}
	rows, _ := st.List(ctx)
	if r := rows["10.0.0.0/24"]; r.Interval == nil || *r.Interval != two || !r.LastRunAt.Equal(ran) || r.LastJobID != "job-1" {
		t.Fatalf("after set+record: %+v", r)
	}
	if err := st.SetInterval(ctx, "10.0.0.0/24", "targeted", "10.0.0.0/24", nil); err != nil {
		t.Fatal(err)
	}
	rows, _ = st.List(ctx)
	if r := rows["10.0.0.0/24"]; r.Interval != nil || !r.LastRunAt.Equal(ran) {
		t.Fatalf("clear must drop the override and keep last_run: %+v", r)
	}
	// The CHECK in the schema rejects sub-minute overrides even from a bad caller.
	tiny := 5 * time.Second
	if err := st.SetInterval(ctx, "x", "targeted", "x", &tiny); err == nil {
		t.Fatal("interval below 60s must be rejected by the schema")
	}
}
