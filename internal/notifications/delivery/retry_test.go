// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package delivery

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// fakeClock is advanced by tests instead of sleeping.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)} }
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// syncWorker drives a Retrier to a final outcome by jumping a fake clock past
// each backoff, for tests that only care about the end state.
type syncWorker struct {
	r   *Retrier
	clk *fakeClock
}

func newSyncWorker(channels []Channel, maxAttempts int) *syncWorker {
	clk := newFakeClock()
	pol := Policy{MaxAttempts: maxAttempts, Base: time.Millisecond, Cap: time.Millisecond, Lease: time.Second}
	return &syncWorker{r: NewRetrier(channels, pol, nil, clk.Now), clk: clk}
}

func (w *syncWorker) Deliver(ctx context.Context, ev Event) Result {
	res := w.r.Deliver(ctx, ev)
	for res.Status == StatusRetrying {
		w.clk.Advance(time.Hour)
		if _, err := w.r.Process(ctx); err != nil {
			panic(err)
		}
		all := w.r.Results()
		if len(all) > 0 && all[len(all)-1].EventID == ev.ID {
			res = all[len(all)-1]
		}
	}
	return res
}

func (w *syncWorker) Results() []Result { return w.r.Results() }

type failingChannel struct {
	name string
	mu   sync.Mutex
	n    int
	err  error // nil = succeed
}

func (c *failingChannel) Name() string { return c.name }
func (c *failingChannel) Send(context.Context, Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	return c.err
}
func (c *failingChannel) calls() int { c.mu.Lock(); defer c.mu.Unlock(); return c.n }

func nextAttemptOf(t *testing.T, st *MemStore, id string) time.Time {
	t.Helper()
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.entries[id].NextAttemptAt
}

func TestBackoffScheduleEightAttemptsThenOneFailure(t *testing.T) {
	clk := newFakeClock()
	ch := &failingChannel{name: "webhook", err: errors.New("down")}
	st := NewMemStore()
	r := NewRetrier([]Channel{ch}, DefaultPolicy(), st, clk.Now)
	r.SetRandom(func() float64 { return 0.5 }) // zero jitter
	var settled []Result
	r.OnSettled = func(_ context.Context, _ Event, res Result) { settled = append(settled, res) }

	ctx := context.Background()
	res := r.Deliver(ctx, Event{ID: "e1", Channel: "webhook"})
	// Delay after attempt n is 1m*2^(n-1), capped at 1h.
	want := []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute, 32 * time.Minute, time.Hour}
	for i, w := range want {
		if res.Status != StatusRetrying {
			t.Fatalf("attempt %d: status %s", i+1, res.Status)
		}
		if got := nextAttemptOf(t, st, "e1").Sub(clk.Now()); got != w {
			t.Fatalf("attempt %d: next in %v, want %v", i+1, got, w)
		}
		// Not due one second early: nothing is attempted.
		clk.Advance(w - time.Second)
		if n, _ := r.Process(ctx); n != 0 {
			t.Fatalf("attempt %d: processed %d entries before due", i+1, n)
		}
		clk.Advance(time.Second)
		if n, err := r.Process(ctx); n != 1 || err != nil {
			t.Fatalf("attempt %d: process = %d, %v", i+1, n, err)
		}
		all := r.Results()
		if i < len(want)-1 && len(all) != 0 {
			t.Fatalf("settled early: %+v", all)
		}
		res = Result{Status: StatusRetrying}
	}
	if ch.calls() != 8 {
		t.Fatalf("channel called %d times, want 8", ch.calls())
	}
	if len(settled) != 1 || settled[0].Status != StatusFailed || settled[0].Attempts != 8 {
		t.Fatalf("want exactly one failed outcome after 8 attempts, got %+v", settled)
	}
	clk.Advance(48 * time.Hour)
	if n, _ := r.Process(ctx); n != 0 || ch.calls() != 8 {
		t.Fatalf("a failed delivery must not be retried again (n=%d calls=%d)", n, ch.calls())
	}
}

func TestBackoffJitterStaysWithinBoundsAndCap(t *testing.T) {
	r := NewRetrier(nil, DefaultPolicy(), nil, nil)
	for n := 1; n <= 12; n++ {
		base := time.Minute << (n - 1)
		if base > time.Hour || base <= 0 {
			base = time.Hour
		}
		for _, f := range []float64{0, 0.25, 0.5, 0.99} {
			r.SetRandom(func() float64 { return f })
			d := r.backoff(n)
			if d > time.Hour {
				t.Fatalf("n=%d f=%v: %v exceeds cap", n, f, d)
			}
			if lo := time.Duration(float64(base) * 0.8); d < lo-time.Second {
				t.Fatalf("n=%d f=%v: %v below %v", n, f, d, lo)
			}
		}
	}
}

func TestRetryAfterHonouredAndCapped(t *testing.T) {
	clk := newFakeClock()
	st := NewMemStore()
	ch := &failingChannel{name: "slack", err: &RetryAfterError{After: 10 * time.Minute, Err: errors.New("429")}}
	r := NewRetrier([]Channel{ch}, DefaultPolicy(), st, clk.Now)
	r.SetRandom(func() float64 { return 0.5 })
	r.Deliver(context.Background(), Event{ID: "ra", Channel: "slack"})
	if got := nextAttemptOf(t, st, "ra").Sub(clk.Now()); got != 10*time.Minute {
		t.Fatalf("Retry-After 10m (> 1m backoff) must win, next in %v", got)
	}

	ch2 := &failingChannel{name: "slack", err: &RetryAfterError{After: 48 * time.Hour, Err: errors.New("429")}}
	r2 := NewRetrier([]Channel{ch2}, DefaultPolicy(), st, clk.Now)
	r2.SetRandom(func() float64 { return 0.5 })
	r2.Deliver(context.Background(), Event{ID: "ra2", Channel: "slack"})
	if got := nextAttemptOf(t, st, "ra2").Sub(clk.Now()); got != time.Hour {
		t.Fatalf("hostile Retry-After must be capped at 1h, next in %v", got)
	}
}

func TestPostJSONSurfacesRetryAfterHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	err := (&WebhookChannel{URL: srv.URL}).Send(context.Background(), Event{Subject: "x"})
	d, ok := RetryAfter(err)
	if !ok || d != 2*time.Minute {
		t.Fatalf("RetryAfter = %v, %v from %v", d, ok, err)
	}
	// A plain 500 carries no hint.
	srv500 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }))
	defer srv500.Close()
	if _, ok := RetryAfter((&WebhookChannel{URL: srv500.URL}).Send(context.Background(), Event{})); ok {
		t.Fatal("500 without header must not carry Retry-After")
	}
}

func TestParseRetryAfterDate(t *testing.T) {
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	d, ok := parseRetryAfter(now.Add(90*time.Second).Format(http.TimeFormat), now)
	if !ok || d != 90*time.Second {
		t.Fatalf("got %v %v", d, ok)
	}
	for _, bad := range []string{"", "0", "-5", "soon", now.Add(-time.Hour).Format(http.TimeFormat)} {
		if _, ok := parseRetryAfter(bad, now); ok {
			t.Errorf("%q should not parse", bad)
		}
	}
}

func openQueueDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func applyQueueMigration(t *testing.T, db *sql.DB) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "db", "migrations", "sqlite", "000381_notification_delivery_queue.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(string(b)); err != nil {
		t.Fatal(err)
	}
}

func TestRestartResumesPersistedRetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "q.db")
	clk := newFakeClock()
	ctx := context.Background()

	db1 := openQueueDB(t, path)
	applyQueueMigration(t, db1)
	bad := &failingChannel{name: "email", err: errors.New("smtp down")}
	r1 := NewRetrier([]Channel{bad}, DefaultPolicy(), NewSQLStore(db1, false), clk.Now)
	if res := r1.Deliver(ctx, Event{ID: "resume", Channel: "email", Target: "a@b.test"}); res.Status != StatusRetrying {
		t.Fatalf("first attempt: %s", res.Status)
	}
	db1.Close() // the process "dies"

	// A new process: fresh retrier and channel over the same database.
	db2 := openQueueDB(t, path)
	good := &failingChannel{name: "email"}
	r2 := NewRetrier([]Channel{good}, DefaultPolicy(), NewSQLStore(db2, false), clk.Now)
	var settled []Result
	var gotEvent Event
	r2.OnSettled = func(_ context.Context, ev Event, res Result) { gotEvent = ev; settled = append(settled, res) }

	if n, _ := r2.Process(ctx); n != 0 {
		t.Fatal("entry must wait for its persisted next_attempt_at")
	}
	clk.Advance(3 * time.Minute) // past the longest first-retry delay (1m +20%)
	if n, err := r2.Process(ctx); n != 1 || err != nil {
		t.Fatalf("resume process = %d, %v", n, err)
	}
	if len(settled) != 1 || settled[0].Status != StatusSent || settled[0].Attempts != 2 {
		t.Fatalf("want one sent outcome on attempt 2, got %+v", settled)
	}
	if gotEvent.Target != "a@b.test" || gotEvent.ID != "resume" {
		t.Fatalf("event not restored: %+v", gotEvent)
	}
	if n, _ := r2.Process(ctx); n != 0 {
		t.Fatal("a sent delivery must not be attempted again")
	}
}

func TestClaimDueIsExclusiveAcrossReplicas(t *testing.T) {
	db := openQueueDB(t, filepath.Join(t.TempDir(), "q.db"))
	applyQueueMigration(t, db)
	a, b := NewSQLStore(db, false), NewSQLStore(db, false)
	now := newFakeClock().Now()
	ctx := context.Background()
	if err := a.Put(ctx, Entry{ID: "x", Event: Event{ID: "x", Channel: "c"}, Attempts: 1, NextAttemptAt: now, Status: StatusRetrying}); err != nil {
		t.Fatal(err)
	}
	first, err := a.ClaimDue(ctx, now, time.Minute, 10)
	if err != nil || len(first) != 1 || first[0].Attempts != 2 {
		t.Fatalf("first claim: %+v %v", first, err)
	}
	second, err := b.ClaimDue(ctx, now, time.Minute, 10)
	if err != nil || len(second) != 0 {
		t.Fatalf("leased entry claimed twice: %+v %v", second, err)
	}
	// A crashed claimer's lease lapses and the entry is due again.
	third, _ := b.ClaimDue(ctx, now.Add(2*time.Minute), time.Minute, 10)
	if len(third) != 1 || third[0].Attempts != 3 {
		t.Fatalf("lapsed lease not reclaimed: %+v", third)
	}
}

func TestPruneDropsOnlySettledRows(t *testing.T) {
	db := openQueueDB(t, filepath.Join(t.TempDir(), "q.db"))
	applyQueueMigration(t, db)
	s := NewSQLStore(db, false)
	ctx := context.Background()
	now := newFakeClock().Now()
	for _, e := range []Entry{
		{ID: "done", Event: Event{ID: "done"}, Status: StatusSent, NextAttemptAt: now},
		{ID: "wait", Event: Event{ID: "wait"}, Status: StatusRetrying, NextAttemptAt: now},
	} {
		if err := s.Put(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Prune(ctx, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Pending(ctx); n != 1 {
		t.Fatalf("pending = %d, want the retrying row kept", n)
	}
	var total int
	_ = db.QueryRow(`SELECT COUNT(*) FROM notification_delivery_queue`).Scan(&total)
	if total != 1 {
		t.Fatalf("rows = %d, want 1", total)
	}
}

func TestRetrierWrapsAnyChannelGenerically(t *testing.T) {
	// A channel the retrier has never heard of (a W38-02 plugin channel would
	// look like this: just Name and Send) gets the same retry behaviour.
	clk := newFakeClock()
	ch := &failingChannel{name: "plugin:teams", err: errors.New("503")}
	r := NewRetrier([]Channel{ch}, Policy{MaxAttempts: 2, Base: time.Minute}, nil, clk.Now)
	if res := r.Deliver(context.Background(), Event{ID: "p", Channel: "plugin:teams"}); res.Status != StatusRetrying {
		t.Fatalf("status = %s", res.Status)
	}
	clk.Advance(time.Hour)
	_, _ = r.Process(context.Background())
	all := r.Results()
	if len(all) != 1 || all[0].Status != StatusFailed || all[0].Attempts != 2 {
		t.Fatalf("results = %+v", all)
	}
}
