// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package connectors

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

type memGateStore struct {
	mu    sync.Mutex
	until map[string]time.Time
	down  bool
}

func newMemGateStore() *memGateStore { return &memGateStore{until: map[string]time.Time{}} }

func (m *memGateStore) Load(_ context.Context, id string) (time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.down {
		return time.Time{}, errors.New("store down")
	}
	return m.until[id], nil
}

func (m *memGateStore) Save(_ context.Context, id string, until time.Time, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.down {
		return errors.New("store down")
	}
	if until.After(m.until[id]) {
		m.until[id] = until
	}
	return nil
}

type memLogStore struct {
	mu   sync.Mutex
	rows map[string][]time.Time
	down bool
}

func newMemLogStore() *memLogStore { return &memLogStore{rows: map[string][]time.Time{}} }

func (m *memLogStore) Append(_ context.Context, id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.down {
		return errors.New("store down")
	}
	m.rows[id] = append(m.rows[id], at)
	return nil
}

func (m *memLogStore) Since(_ context.Context, id string, since time.Time) ([]time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.down {
		return nil, errors.New("store down")
	}
	var out []time.Time
	for _, r := range m.rows[id] {
		if r.After(since) {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *memLogStore) Prune(_ context.Context, id string, before time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var keep []time.Time
	for _, r := range m.rows[id] {
		if r.After(before) {
			keep = append(keep, r)
		}
	}
	m.rows[id] = keep
	return nil
}

func rateLimited(d time.Duration) error {
	return &RateLimitError{ConnectorID: "c", Reason: "upstream_429", RetryAfter: d}
}

func mustAcquire(t *testing.T, th *Throttle, id string) {
	t.Helper()
	rel, err := th.Acquire(context.Background(), id)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	rel(nil)
}

func TestRetryGateSurvivesRestart(t *testing.T) {
	clk := newClock()
	store := newMemGateStore()
	a := NewThrottle(Limits{}, clk.Now)
	a.SetStores(store, nil)
	rel, err := a.Acquire(context.Background(), "c")
	if err != nil {
		t.Fatal(err)
	}
	rel(rateLimited(10 * time.Minute))

	// A fresh Throttle is a restarted process: nothing in memory.
	b := NewThrottle(Limits{}, clk.Now)
	b.SetStores(store, nil)
	_, err = b.Acquire(context.Background(), "c")
	var rl *RateLimitError
	if !errors.As(err, &rl) || rl.Reason != "backoff" {
		t.Fatalf("restarted throttle placed an order inside the hold: %v", err)
	}
	if rl.RetryAfter != 10*time.Minute {
		t.Fatalf("retry after = %s, want 10m", rl.RetryAfter)
	}
	clk.Advance(10*time.Minute - time.Second)
	if _, err := b.Acquire(context.Background(), "c"); err == nil {
		t.Fatal("admitted one second before retry_at")
	}
	clk.Advance(time.Second)
	mustAcquire(t, b, "c")
}

func TestRetryGateSharedByReplicas(t *testing.T) {
	clk := newClock()
	store := newMemGateStore()
	a, b := NewThrottle(Limits{}, clk.Now), NewThrottle(Limits{}, clk.Now)
	a.SetStores(store, nil)
	b.SetStores(store, nil)
	rel, _ := a.Acquire(context.Background(), "c")
	rel(rateLimited(time.Hour))
	if _, err := b.Acquire(context.Background(), "c"); err == nil {
		t.Fatal("replica B ordered while replica A held the connector")
	}
	mustAcquire(t, b, "other") // another connector is unaffected
}

func TestUpstreamGateHoldIsShared(t *testing.T) {
	store := newMemGateStore()
	a, b := NewThrottle(Limits{}, time.Now), NewThrottle(Limits{}, time.Now)
	a.SetStores(store, nil)
	b.SetStores(store, nil)
	ga := (&Registry{}).withGate(context.Background(), a, "c")
	gb := (&Registry{}).withGate(context.Background(), b, "c")
	UpstreamGateFrom(ga).NoteRetryAfter(200 * time.Millisecond)
	start := time.Now()
	if err := UpstreamGateFrom(gb).Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if el := time.Since(start); el < 150*time.Millisecond {
		t.Fatalf("replica B's gate released after %s, before the shared hold ended", el)
	}
}

func TestRetryGateStoreDownFailsOpenButKeepsMemoryHold(t *testing.T) {
	clk := newClock()
	store := newMemGateStore()
	store.down = true
	th := NewThrottle(Limits{}, clk.Now)
	th.SetStores(store, nil)
	mustAcquire(t, th, "c") // an unreadable store must not stop issuance
	rel, _ := th.Acquire(context.Background(), "c")
	rel(rateLimited(time.Minute)) // Save fails; the in-memory backoff still applies
	if _, err := th.Acquire(context.Background(), "c"); err == nil {
		t.Fatal("in-memory backoff lost when the store is down")
	}
	clk.Advance(time.Minute)
	mustAcquire(t, th, "c")
}

func windowThrottle(clk *fakeClock, log IssueLogStore) *Throttle {
	th := NewThrottle(Limits{Window: time.Hour, WindowBudget: 3}, clk.Now)
	th.SetStores(nil, log)
	return th
}

func TestWindowBudgetRolling(t *testing.T) {
	clk := newClock()
	th := windowThrottle(clk, nil)
	for i := 0; i < 3; i++ {
		mustAcquire(t, th, "c")
		clk.Advance(10 * time.Minute)
	}
	// Orders at 0, 10, 20 min; now 30 min.
	_, err := th.Acquire(context.Background(), "c")
	var rl *RateLimitError
	if !errors.As(err, &rl) || rl.Reason != "window_budget" {
		t.Fatalf("order N+1 not refused: %v", err)
	}
	if rl.RetryAfter != 30*time.Minute {
		t.Fatalf("retry after = %s, want 30m (until the oldest order leaves)", rl.RetryAfter)
	}
	clk.Advance(30*time.Minute - time.Nanosecond)
	if _, err := th.Acquire(context.Background(), "c"); err == nil {
		t.Fatal("admitted a nanosecond before the oldest order left the window")
	}
	clk.Advance(time.Nanosecond) // exactly oldest + window
	mustAcquire(t, th, "c")
	if _, err := th.Acquire(context.Background(), "c"); err == nil {
		t.Fatal("window allowed a fourth order")
	}
}

func TestWindowBudgetSurvivesRestartAndIsPruned(t *testing.T) {
	clk := newClock()
	log := newMemLogStore()
	a := windowThrottle(clk, log)
	for i := 0; i < 3; i++ {
		mustAcquire(t, a, "c")
	}
	b := windowThrottle(clk, log) // restarted
	if _, err := b.Acquire(context.Background(), "c"); err == nil {
		t.Fatal("restarted throttle forgot the window")
	}
	clk.Advance(time.Hour)
	mustAcquire(t, b, "c")
	if n := len(log.rows["c"]); n != 1 {
		t.Fatalf("log holds %d rows, want only the order inside the window", n)
	}
}

func TestWindowBudgetStoreDownFallsBackToMemory(t *testing.T) {
	clk := newClock()
	log := newMemLogStore()
	log.down = true
	th := windowThrottle(clk, log)
	for i := 0; i < 3; i++ {
		mustAcquire(t, th, "c")
	}
	if _, err := th.Acquire(context.Background(), "c"); err == nil {
		t.Fatal("window not enforced from memory while the store is down")
	}
}

func TestWindowBudgetSkipsRevocationAndSnapshotShowsUsage(t *testing.T) {
	clk := newClock()
	th := NewThrottle(Limits{Window: time.Hour, WindowBudget: 1, DailyBudget: 5}, clk.Now)
	rel, err := th.acquire(context.Background(), "c", false)
	if err != nil {
		t.Fatal(err)
	}
	rel(nil)
	mustAcquire(t, th, "c")
	if _, err := th.Acquire(context.Background(), "c"); err == nil {
		t.Fatal("second order inside the window admitted")
	}
	st := th.Snapshot()[0]
	if st.WindowBudget != 1 || st.WindowUsed != 1 || st.WindowSeconds != 3600 || st.DailyUsed != 1 {
		t.Fatalf("snapshot = %+v", st)
	}
}

func TestWindowFromEnvAndConfig(t *testing.T) {
	env := map[string]string{envLimits: `{"a":{"window":"2h","window_budget":4},"b":{"window":7200,"window_budget":2},"bad":{"window":"2h"},"neg":{"window":"-1h","window_budget":1}}`}
	_, per := LimitsFromEnv(func(k string) string { return env[k] })
	if per["a"].Window != 2*time.Hour || per["a"].WindowBudget != 4 || per["b"].Window != 2*time.Hour || per["b"].WindowBudget != 2 {
		t.Fatalf("per = %+v", per)
	}
	if per["bad"].Window != 0 || per["neg"].Window != 0 {
		t.Fatalf("invalid windows accepted: %+v", per)
	}
	th := NewThrottle(Limits{}, nil)
	th.SetLimits("a", per["a"])
	th.ConfigureWindow("a", time.Minute, 9) // the env entry wins
	th.ConfigureWindow("cfg", time.Minute, 9)
	if l := th.limitsLocked("a"); l.WindowBudget != 4 {
		t.Fatalf("config overrode env: %+v", l)
	}
	if l := th.limitsLocked("cfg"); l.Window != time.Minute || l.WindowBudget != 9 {
		t.Fatalf("config window not applied: %+v", l)
	}
	if _, err := ParseWindow(json.RawMessage(`"99999h"`)); err == nil {
		t.Fatal("oversize window accepted")
	}
}
