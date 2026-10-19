// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func newTestPostureStore(t *testing.T) *dbPostureSnapshotStore {
	t.Helper()
	return newTestPostureStoreAt(t, filepath.Join(t.TempDir(), "posture.db"))
}

func newTestPostureStoreAt(t *testing.T, dbPath string) *dbPostureSnapshotStore {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open temp db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	store := &dbPostureSnapshotStore{db: db, ph: sqlitePlaceholder}
	if err := store.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("ensure schema: %v", err)
	}
	return store
}

func sampleReport(total, pqc, automation int) CryptoPostureReport {
	r := CryptoPostureReport{
		GeneratedAt:        time.Now().UTC().Format(time.RFC3339),
		TotalCerts:         total,
		AlgorithmBreakdown: map[string]int{"RSA": total},
		GradeDistribution:  map[string]int{"A": total},
	}
	r.PQCReadiness.PQCScorePercent = pqc
	r.AutomationCoverage.AutomationPercent = automation
	r.RiskBreakdown.Critical = 1
	r.RiskBreakdown.High = 2
	r.ExpiryBuckets.Expiring47d = 3
	return r
}

func TestPostureSnapshotStoreSaveAndList(t *testing.T) {
	store := newTestPostureStore(t)
	ctx := context.Background()

	day1 := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC).Format(time.RFC3339)
	day2 := time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC).Format(time.RFC3339)

	if err := store.Save(ctx, snapshotFromReport("psn-1", day1, sampleReport(10, 40, 50))); err != nil {
		t.Fatalf("save 1: %v", err)
	}
	if err := store.Save(ctx, snapshotFromReport("psn-2", day2, sampleReport(12, 55, 60))); err != nil {
		t.Fatalf("save 2: %v", err)
	}

	got, err := store.List(ctx, "2026-01-01T00:00:00Z", 100)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 snapshots, got %d", len(got))
	}
	// ASC order by captured_at.
	if got[0].ID != "psn-1" || got[1].ID != "psn-2" {
		t.Fatalf("unexpected order: %s, %s", got[0].ID, got[1].ID)
	}
	if got[1].PQCScorePercent != 55 || got[1].AutomationPercent != 60 {
		t.Fatalf("flattened fields wrong: %+v", got[1])
	}
	// Full report round-trips via report_json.
	if got[1].Report.TotalCerts != 12 || got[1].Report.AlgorithmBreakdown["RSA"] != 12 {
		t.Fatalf("report json did not round-trip: %+v", got[1].Report)
	}
}

func TestPostureSnapshotStoreSinceFilter(t *testing.T) {
	store := newTestPostureStore(t)
	ctx := context.Background()

	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	recent := time.Date(2026, 6, 10, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	_ = store.Save(ctx, snapshotFromReport("psn-old", old, sampleReport(1, 1, 1)))
	_ = store.Save(ctx, snapshotFromReport("psn-new", recent, sampleReport(2, 2, 2)))

	got, err := store.List(ctx, "2026-06-01T00:00:00Z", 100)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0].ID != "psn-new" {
		t.Fatalf("since filter failed: %+v", got)
	}
}

func TestPostureSnapshotStoreLatest(t *testing.T) {
	store := newTestPostureStore(t)
	ctx := context.Background()

	if _, ok, err := store.Latest(ctx); err != nil || ok {
		t.Fatalf("expected no latest on empty store, ok=%v err=%v", ok, err)
	}

	d1 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	d2 := time.Date(2026, 6, 5, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	_ = store.Save(ctx, snapshotFromReport("psn-1", d1, sampleReport(1, 1, 1)))
	_ = store.Save(ctx, snapshotFromReport("psn-2", d2, sampleReport(2, 2, 2)))

	latest, ok, err := store.Latest(ctx)
	if err != nil || !ok {
		t.Fatalf("expected latest, ok=%v err=%v", ok, err)
	}
	if latest.ID != "psn-2" {
		t.Fatalf("expected psn-2 as latest, got %s", latest.ID)
	}
}

func TestDayKey(t *testing.T) {
	if got := dayKey("2026-06-15T12:34:56Z"); got != "2026-06-15" {
		t.Fatalf("dayKey: got %q", got)
	}
	if got := dayKey("short"); got != "short" {
		t.Fatalf("dayKey short: got %q", got)
	}
}

func TestPostureSnapshotStorePruneDeletesOnlyOlderRows(t *testing.T) {
	store := newTestPostureStore(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	at := func(days int) string { return now.AddDate(0, 0, -days).Format(time.RFC3339) }
	for id, days := range map[string]int{"psn-old": 401, "psn-edge": 399, "psn-now": 0} {
		if err := store.Save(ctx, snapshotFromReport(id, at(days), sampleReport(1, 1, 1))); err != nil {
			t.Fatalf("save %s: %v", id, err)
		}
	}
	res, err := store.Prune(ctx, at(400))
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if res.Deleted != 1 || res.Oldest != at(401) || res.Newest != at(401) {
		t.Fatalf("unexpected prune result: %+v", res)
	}
	got, err := store.List(ctx, "2000-01-01T00:00:00Z", 100)
	if err != nil || len(got) != 2 {
		t.Fatalf("expected 2 survivors, got %d (err %v)", len(got), err)
	}
	if res, err := store.Prune(ctx, at(400)); err != nil || res.Deleted != 0 {
		t.Fatalf("second prune: %+v %v", res, err)
	}
}

func TestPostureSnapshotStoreSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "restart.db")
	first := newTestPostureStoreAt(t, path)
	ctx := context.Background()
	for i := 1; i <= 3; i++ {
		ts := time.Date(2026, 6, i, 12, 0, 0, 0, time.UTC).Format(time.RFC3339)
		if err := first.Save(ctx, snapshotFromReport(fmt.Sprintf("psn-%d", i), ts, sampleReport(i, 1, 1))); err != nil {
			t.Fatalf("save %d: %v", i, err)
		}
	}
	second := newTestPostureStoreAt(t, path)
	got, err := second.List(ctx, "2000-01-01T00:00:00Z", 100)
	if err != nil || len(got) != 3 {
		t.Fatalf("expected 3 rows after reopen, got %d (err %v)", len(got), err)
	}
}
