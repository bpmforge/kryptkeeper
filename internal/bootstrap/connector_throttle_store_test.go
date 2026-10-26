// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"kryptkeeper/internal/connectors"
	kkdb "kryptkeeper/internal/db"
)

func TestConnectorThrottleStoreGateKeepsLaterDeadline(t *testing.T) {
	runGateKeepsLaterDeadline(t, newDBConnectorThrottleStore(openMigratedKeyDB(t, filepath.Join(t.TempDir(), "k.db")), false))
}

func TestConnectorThrottleStore_Postgres(t *testing.T) {
	dsn := os.Getenv("KRYPTKEEPER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("KRYPTKEEPER_TEST_POSTGRES_DSN not set — skipping live Postgres store test")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := kkdb.RunMigrations(db, "postgres"); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	// A previous run may have left rows; these connector ids are unique to this test.
	_, _ = db.Exec(`DELETE FROM connector_retry_gate WHERE connector_id IN ('c','other')`)
	_, _ = db.Exec(`DELETE FROM connector_issue_log WHERE connector_id IN ('c','other')`)
	st := newDBConnectorThrottleStore(db, true)
	runGateKeepsLaterDeadline(t, st)
	runIssueLog(t, st)
}

func runGateKeepsLaterDeadline(t *testing.T, st *dbConnectorThrottleStore) {
	t.Helper()
	ctx := context.Background()
	if got, err := st.Load(ctx, "c"); err != nil || !got.IsZero() {
		t.Fatalf("empty load = %v, %v", got, err)
	}
	// Microsecond precision: Postgres TIMESTAMPTZ stores no finer.
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 123456000, time.UTC)
	if err := st.Save(ctx, "c", t0.Add(time.Hour), "backoff"); err != nil {
		t.Fatal(err)
	}
	if err := st.Save(ctx, "c", t0.Add(time.Minute), "retry_after"); err != nil { // a racing replica with an earlier deadline
		t.Fatal(err)
	}
	got, err := st.Load(ctx, "c")
	if err != nil || !got.Equal(t0.Add(time.Hour)) {
		t.Fatalf("load = %v, %v; want the later deadline %v", got, err, t0.Add(time.Hour))
	}
}

func TestConnectorThrottleStoreIssueLog(t *testing.T) {
	runIssueLog(t, newDBConnectorThrottleStore(openMigratedKeyDB(t, filepath.Join(t.TempDir(), "k.db")), false))
}

func runIssueLog(t *testing.T, st *dbConnectorThrottleStore) {
	t.Helper()
	ctx := context.Background()
	base := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 4; i++ {
		if err := st.Append(ctx, "c", base.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	_ = st.Append(ctx, "other", base)
	got, err := st.Since(ctx, "c", base.Add(30*time.Second))
	if err != nil || len(got) != 3 || !got[0].Equal(base.Add(time.Minute)) {
		t.Fatalf("since = %v, %v", got, err)
	}
	if err := st.Prune(ctx, "c", base.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.Since(ctx, "c", base.Add(-time.Hour)); len(got) != 2 {
		t.Fatalf("after prune = %v", got)
	}
	if got, _ := st.Since(ctx, "other", base.Add(-time.Hour)); len(got) != 1 {
		t.Fatal("prune crossed connectors")
	}
}

func TestThrottleOnRealStoreSurvivesRestart(t *testing.T) {
	db := openMigratedKeyDB(t, filepath.Join(t.TempDir(), "k.db"))
	now := time.Now()
	mk := func() *connectors.Throttle {
		th := connectors.NewThrottle(connectors.Limits{Window: time.Hour, WindowBudget: 2}, func() time.Time { return now })
		attachConnectorThrottleStores(th, db, false)
		return th
	}
	a := mk()
	for i := 0; i < 2; i++ {
		rel, err := a.Acquire(context.Background(), "c")
		if err != nil {
			t.Fatal(err)
		}
		rel(nil)
	}
	if _, err := mk().Acquire(context.Background(), "c"); err == nil {
		t.Fatal("restarted throttle ignored the persisted window")
	}
	rel, _ := mk().Acquire(context.Background(), "fresh")
	rel(&connectors.RateLimitError{ConnectorID: "fresh", Reason: "upstream_429", RetryAfter: time.Hour})
	if _, err := mk().Acquire(context.Background(), "fresh"); err == nil {
		t.Fatal("restarted throttle ignored the persisted retry_at")
	}
}

func TestApplyConnectorWindowConfig(t *testing.T) {
	th := connectors.NewThrottle(connectors.Limits{}, nil)
	applyConnectorWindowConfig(th, ConnectorRecord{ID: "a", ConfigJSON: `{"rate_window":"1h","rate_budget":2}`})
	applyConnectorWindowConfig(th, ConnectorRecord{ID: "bad", ConfigJSON: `{"rate_window":"1h"}`})
	rel, err := th.Acquire(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	rel(nil)
	rel, _ = th.Acquire(context.Background(), "bad")
	rel(nil)
	snap := map[string]connectors.ThrottleStatus{}
	for _, s := range th.Snapshot() {
		snap[s.ConnectorID] = s
	}
	if snap["a"].WindowBudget != 2 || snap["a"].WindowUsed != 1 || snap["bad"].WindowBudget != 0 {
		t.Fatalf("snapshot = %+v", snap)
	}
}
