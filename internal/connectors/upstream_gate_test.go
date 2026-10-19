// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package connectors

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A call that was already in flight when a sibling drew a 429 can still
// succeed; that success used to wipe the sibling's backoff, letting the next
// Acquire straight through the upstream's Retry-After.
func TestSuccessDoesNotEraseSiblingBackoff(t *testing.T) {
	clk := newClock()
	th := NewThrottle(Limits{MaxConcurrent: 4}, clk.Now)
	ctx := context.Background()
	limited, err := th.Acquire(ctx, "c1")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := th.Acquire(ctx, "c1")
	if err != nil {
		t.Fatal(err)
	}
	limited(&RateLimitError{Reason: "upstream_429", RetryAfter: time.Minute})
	ok(nil)
	_, err = th.Acquire(ctx, "c1")
	var rl *RateLimitError
	if !errors.As(err, &rl) || rl.Reason != "backoff" {
		t.Fatalf("a sibling's success cleared the backoff: %v", err)
	}
	clk.Advance(time.Minute + time.Second)
	release, err := th.Acquire(ctx, "c1")
	if err != nil {
		t.Fatalf("backoff must lapse on its own: %v", err)
	}
	release(nil)
	if s := th.Snapshot()[0]; s.RateLimitedTotal != 1 {
		t.Fatalf("snapshot: %+v", s)
	}
}

func TestMinBackoffFromEnv(t *testing.T) {
	env := func(v string) func(string) string {
		return func(k string) string {
			if k != "KRYPTKEEPER_CONNECTOR_MIN_BACKOFF" {
				t.Fatalf("unexpected key %s", k)
			}
			return v
		}
	}
	for in, want := range map[string]time.Duration{
		"": 30 * time.Second, "500ms": 500 * time.Millisecond, "2m": 2 * time.Minute,
		"junk": 30 * time.Second, "-1s": 30 * time.Second, "0": 30 * time.Second, "25h": 30 * time.Second,
	} {
		if got := MinBackoffFromEnv(env(in)); got != want {
			t.Errorf("MinBackoffFromEnv(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestThrottleBackoffFloorIsConfigurable(t *testing.T) {
	clk := newClock()
	th := NewThrottle(Limits{MaxConcurrent: 1}, clk.Now)
	th.minBackoff = 500 * time.Millisecond
	release, _ := th.Acquire(context.Background(), "c1")
	release(&RateLimitError{Reason: "upstream_429"})
	_, err := th.Acquire(context.Background(), "c1")
	var rl *RateLimitError
	if !errors.As(err, &rl) || rl.RetryAfter != 500*time.Millisecond {
		t.Fatalf("backoff = %v, want the configured 500ms floor", err)
	}
	if got := NewThrottle(Limits{}, nil).minBackoff; got != 30*time.Second {
		t.Fatalf("default floor changed: %s", got)
	}
}

type gateProbe struct {
	IssuerConnector
	issue func(ctx context.Context) error
}

func (g gateProbe) ID() string     { return "gate" }
func (g gateProbe) Type() string   { return "acme" }
func (g gateProbe) Origin() string { return "synced" }
func (g gateProbe) Issue(ctx context.Context, _ IssueRequest) (IssueResult, error) {
	return IssueResult{}, g.issue(ctx)
}

func TestUpstreamGateParksSiblingUntilRetryAfter(t *testing.T) {
	th := NewThrottle(Limits{MaxConcurrent: 4}, time.Now)
	noted := make(chan struct{})
	var waited time.Duration
	first := gateProbe{issue: func(ctx context.Context) error {
		UpstreamGateFrom(ctx).NoteRetryAfter(300 * time.Millisecond)
		close(noted)
		return nil
	}}
	second := gateProbe{issue: func(ctx context.Context) error {
		start := time.Now()
		err := UpstreamGateFrom(ctx).Wait(ctx)
		waited = time.Since(start)
		return err
	}}
	reg := NewRegistry().WithThrottle(th)
	reg.Register(first)
	if _, err := reg.Issue(context.Background(), "gate", IssueRequest{}); err != nil {
		t.Fatal(err)
	}
	<-noted
	reg2 := NewRegistry().WithThrottle(th)
	reg2.Register(second)
	if _, err := reg2.Issue(context.Background(), "gate", IssueRequest{}); err != nil {
		t.Fatal(err)
	}
	if waited < 200*time.Millisecond {
		t.Fatalf("sibling was not parked behind the hold (waited %s)", waited)
	}
	// With no hold the gate is free, and a nil gate (connector used outside a registry) is inert.
	if err := UpstreamGateFrom(context.Background()).Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestUpstreamGateWaitEndsOnDrainAndContext(t *testing.T) {
	th := NewThrottle(Limits{}, time.Now)
	th.hold("gate", time.Minute)
	drain := make(chan struct{})
	g := &UpstreamGate{t: th, id: "gate", drain: drain}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := g.Wait(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ctx end: %v", err)
	}
	go func() { time.Sleep(30 * time.Millisecond); close(drain) }()
	start := time.Now()
	err := g.Wait(context.Background())
	var rl *RateLimitError
	if !errors.As(err, &rl) || rl.Reason != "shutdown" || time.Since(start) > 5*time.Second {
		t.Fatalf("drain: err=%v after %s", err, time.Since(start))
	}
	if !g.Draining() {
		t.Fatal("Draining must report the closed channel")
	}
}
