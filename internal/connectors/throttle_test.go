// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package connectors

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

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

func newClock() *fakeClock { return &fakeClock{t: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)} }

func TestThrottleNeverExceedsCap(t *testing.T) {
	th := NewThrottle(Limits{MaxConcurrent: 10}, time.Now)
	var cur, peak int32
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := th.Acquire(context.Background(), "c1")
			if err != nil {
				t.Error(err)
				return
			}
			n := atomic.AddInt32(&cur, 1)
			for {
				p := atomic.LoadInt32(&peak)
				if n <= p || atomic.CompareAndSwapInt32(&peak, p, n) {
					break
				}
			}
			time.Sleep(time.Millisecond)
			atomic.AddInt32(&cur, -1)
			release(nil)
		}()
	}
	wg.Wait()
	if peak > 10 || peak == 0 {
		t.Fatalf("peak in-flight = %d, want 1..10", peak)
	}
	if st := th.Snapshot(); len(st) != 1 || st[0].InFlight != 0 || st[0].Waiting != 0 {
		t.Fatalf("throttle must drain: %+v", st)
	}
}

func TestRetryAfterBacksOffExponentially(t *testing.T) {
	clk := newClock()
	th := NewThrottle(Limits{MaxConcurrent: 2}, clk.Now)
	var events []ThrottleEvent
	th.SetObserver(func(e ThrottleEvent) { events = append(events, e) })
	limited := &RateLimitError{ConnectorID: "c1", Reason: "upstream_429"}

	fail := func() {
		release, err := th.Acquire(context.Background(), "c1")
		if err != nil {
			t.Fatal(err)
		}
		release(limited)
	}
	blocked := func(want time.Duration) {
		t.Helper()
		_, err := th.Acquire(context.Background(), "c1")
		var rl *RateLimitError
		if !errors.As(err, &rl) || rl.Reason != "backoff" || rl.RetryAfter != want {
			t.Fatalf("want backoff %v, got %v", want, err)
		}
	}
	fail()
	blocked(30 * time.Second)
	clk.Advance(31 * time.Second)
	fail()
	blocked(time.Minute)
	for i := 0; i < 10; i++ {
		clk.Advance(2 * time.Hour)
		fail()
	}
	blocked(time.Hour) // capped
	clk.Advance(2 * time.Hour)
	release, err := th.Acquire(context.Background(), "c1")
	if err != nil {
		t.Fatal(err)
	}
	release(nil) // success resets the streak
	fail()
	blocked(30 * time.Second)
	if len(events) != 13 || events[0].Reason != "upstream_429" || events[1].RetryAfter != time.Minute || events[1].Failures != 2 {
		t.Fatalf("observer events wrong: %+v", events)
	}
	if st := th.Snapshot(); st[0].RateLimitedTotal != 13 || st[0].BlockedUntil == "" {
		t.Fatalf("snapshot: %+v", st)
	}
}

func TestRetryAfterHonouredWhenLongerThanBackoff(t *testing.T) {
	clk := newClock()
	th := NewThrottle(Limits{}, clk.Now)
	release, _ := th.Acquire(context.Background(), "c1")
	release(&RateLimitError{RetryAfter: 10 * time.Minute})
	if _, err := th.Acquire(context.Background(), "c1"); err == nil {
		t.Fatal("must be blocked")
	} else if rl := err.(*RateLimitError); rl.RetryAfter != 10*time.Minute {
		t.Fatalf("Retry-After longer than the backoff must win: %v", rl.RetryAfter)
	}
}

func TestRetryAfterHeaderParsing(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	cases := map[string]time.Duration{
		"120":       2 * time.Minute,
		"0":         0,
		"":          0,
		"garbage":   0,
		"-5":        0,
		"999999999": 24 * time.Hour,
		now.Add(90 * time.Second).Format(http.TimeFormat): 90 * time.Second,
		now.Add(-time.Hour).Format(http.TimeFormat):       0,
		now.Add(100 * time.Hour).Format(http.TimeFormat):  24 * time.Hour,
	}
	for in, want := range cases {
		if got := ParseRetryAfter(in, now); got != want {
			t.Errorf("ParseRetryAfter(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestAcmeErrorRecognised(t *testing.T) {
	h := http.Header{}
	h.Set("Retry-After", "45")
	err := fmt.Errorf("order: %w", &acme.Error{StatusCode: 429, Header: h})
	if d, ok := RetryAfterOf(err); !ok || d != 45*time.Second {
		t.Fatalf("got %v %v", d, ok)
	}
	if d, ok := RetryAfterOf(&acme.Error{StatusCode: 429}); !ok || d != 0 {
		t.Fatalf("absent header must still be a rate limit: %v %v", d, ok)
	}
	if _, ok := RetryAfterOf(&acme.Error{StatusCode: 500}); ok {
		t.Fatal("500 is not a rate limit")
	}
	if _, ok := RetryAfterOf(errors.New("boom")); ok {
		t.Fatal("plain error is not a rate limit")
	}
}

func TestDailyBudgetRefusesThenResetsAtUTCMidnight(t *testing.T) {
	clk := &fakeClock{t: time.Date(2026, 10, 1, 23, 0, 0, 0, time.UTC)}
	th := NewThrottle(Limits{MaxConcurrent: 5, DailyBudget: 2}, clk.Now)
	for i := 0; i < 2; i++ {
		release, err := th.Acquire(context.Background(), "ca")
		if err != nil {
			t.Fatal(err)
		}
		release(nil)
	}
	_, err := th.Acquire(context.Background(), "ca")
	var rl *RateLimitError
	if !errors.As(err, &rl) || rl.Reason != "daily_budget" || rl.RetryAfter != time.Hour {
		t.Fatalf("budget must refuse until midnight: %v", err)
	}
	if st := th.Snapshot()[0]; st.DailyUsed != 2 || st.DailyBudget != 2 {
		t.Fatalf("snapshot: %+v", st)
	}
	clk.Advance(time.Hour)
	if release, err := th.Acquire(context.Background(), "ca"); err != nil {
		t.Fatalf("budget must reset at UTC midnight: %v", err)
	} else {
		release(nil)
	}
	th.SetLimits("other", Limits{DailyBudget: 1})
	r, _ := th.Acquire(context.Background(), "other")
	r(nil)
	if _, err := th.Acquire(context.Background(), "other"); err == nil {
		t.Fatal("per-connector budget must apply")
	}
	if r, err := th.Acquire(context.Background(), "ca"); err != nil {
		t.Fatalf("other connector's budget must not leak: %v", err)
	} else {
		r(nil)
	}
}

func TestAcquireHonoursContext(t *testing.T) {
	th := NewThrottle(Limits{MaxConcurrent: 1}, time.Now)
	hold, _ := th.Acquire(context.Background(), "c1")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := th.Acquire(ctx, "c1"); done <- err }()
	for th.Snapshot()[0].Waiting == 0 {
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	if th.Snapshot()[0].Waiting != 0 {
		t.Fatal("cancelled waiter must leave the queue")
	}
	hold(nil)
	if r, err := th.Acquire(context.Background(), "c1"); err != nil {
		t.Fatal(err)
	} else {
		r(nil)
	}
}

func TestLimitsFromEnv(t *testing.T) {
	env := map[string]string{
		"KRYPTKEEPER_CONNECTOR_MAX_CONCURRENT": "4",
		"KRYPTKEEPER_CONNECTOR_DAILY_BUDGET":   "100",
		"KRYPTKEEPER_CONNECTOR_LIMITS":         `{"le":{"max_concurrent":2,"daily_budget":300},"bad":{"max_concurrent":-1}}`,
	}
	def, per := LimitsFromEnv(func(k string) string { return env[k] })
	if def != (Limits{MaxConcurrent: 4, DailyBudget: 100}) {
		t.Fatalf("def = %+v", def)
	}
	if per["le"] != (Limits{MaxConcurrent: 2, DailyBudget: 300}) || len(per) != 1 {
		t.Fatalf("per = %+v", per)
	}
	def, per = LimitsFromEnv(func(string) string { return "" })
	if def != (Limits{MaxConcurrent: 10}) || len(per) != 0 {
		t.Fatalf("defaults wrong: %+v %+v", def, per)
	}
	def, per = LimitsFromEnv(func(k string) string {
		return map[string]string{"KRYPTKEEPER_CONNECTOR_MAX_CONCURRENT": "zero", "KRYPTKEEPER_CONNECTOR_LIMITS": "{"}[k]
	})
	if def.MaxConcurrent != 10 || len(per) != 0 {
		t.Fatalf("invalid values must fall back: %+v %+v", def, per)
	}
}

func TestRegistryIssueUsesThrottle(t *testing.T) {
	th := NewThrottle(Limits{MaxConcurrent: 1, DailyBudget: 1}, time.Now)
	reg := NewRegistry().WithThrottle(th)
	reg.Register(fakeConnector{id: "c1", typ: "fake", origin: "synced"})
	if _, err := reg.Issue(context.Background(), "c1", IssueRequest{CSRPEM: "x"}); err != nil {
		t.Fatal(err)
	}
	_, err := reg.Issue(context.Background(), "c1", IssueRequest{CSRPEM: "x"})
	var rl *RateLimitError
	if !errors.As(err, &rl) || rl.Reason != "daily_budget" {
		t.Fatalf("registry must gate on the throttle: %v", err)
	}
	if _, err := reg.Issue(context.Background(), "missing", IssueRequest{}); !errors.Is(err, ErrConnectorNotFound) {
		t.Fatalf("unknown connector error changed: %v", err)
	}
}

type limitedConnector struct{ fakeConnector }

func (limitedConnector) Issue(context.Context, IssueRequest) (IssueResult, error) {
	return IssueResult{}, &RateLimitError{ConnectorID: "rl", Reason: "upstream_429", RetryAfter: time.Minute}
}

func TestRegistryIssueReturnsOriginalErrorAndBacksOff(t *testing.T) {
	th := NewThrottle(Limits{}, time.Now)
	reg := NewRegistry().WithThrottle(th)
	reg.Register(limitedConnector{fakeConnector{id: "rl"}})
	_, err := reg.Issue(context.Background(), "rl", IssueRequest{})
	var rl *RateLimitError
	if !errors.As(err, &rl) || rl.Reason != "upstream_429" {
		t.Fatalf("original error must be returned unchanged: %v", err)
	}
	_, err = reg.Issue(context.Background(), "rl", IssueRequest{})
	if !errors.As(err, &rl) || rl.Reason != "backoff" {
		t.Fatalf("next call must be refused by the backoff window: %v", err)
	}
}
