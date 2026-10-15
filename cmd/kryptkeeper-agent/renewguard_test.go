// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"kryptkeeper/internal/agentclient"
)

func testGuard(clock *time.Time) *renewGuard {
	g := newRenewGuard()
	g.now = func() time.Time { return *clock }
	g.jitter = func(d time.Duration) time.Duration { return d }
	return g
}

// A hub that keeps returning the same pending task on every poll must not
// start a second renewal while the first is running (it would bind :80 twice).
func TestDispatchRenewals_NeverRunsConcurrently(t *testing.T) {
	g := newRenewGuard()
	task := agentclient.RenewalTask{TaskID: "t1", Fingerprint: "ab", Action: "renew"}
	var running, peak, runs atomic.Int32
	release := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	run := func(agentclient.RenewalTask) error {
		defer wg.Done()
		runs.Add(1)
		n := running.Add(1)
		if n > peak.Load() {
			peak.Store(n)
		}
		<-release
		running.Add(-1)
		return nil
	}
	for range 5 { // five polls while the first renewal is still in flight
		g.dispatchRenewals([]agentclient.RenewalTask{task}, run)
	}
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()
	if runs.Load() != 1 || peak.Load() != 1 {
		t.Fatalf("runs=%d peak=%d, want 1/1", runs.Load(), peak.Load())
	}
}

// Two different certificates also share :80, so they are serialised too.
func TestRenewGuard_OneRenewalAcrossTasks(t *testing.T) {
	g := newRenewGuard()
	if !g.start("a") {
		t.Fatal("first start refused")
	}
	if g.start("b") {
		t.Fatal("second task admitted while first running")
	}
	g.finish("a", nil)
	if !g.start("b") {
		t.Fatal("slot not released")
	}
}

func TestRenewGuard_BackoffSchedule(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	g := testGuard(&clock)
	fail := errors.New("boom")
	want := []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute,
		16 * time.Minute, 32 * time.Minute, time.Hour, time.Hour}
	for i, d := range want {
		if !g.start("k") {
			t.Fatalf("attempt %d refused", i)
		}
		g.finish("k", fail)
		clock = clock.Add(d - time.Second)
		if g.start("k") {
			t.Fatalf("attempt %d: retried 1s early", i)
		}
		clock = clock.Add(time.Second)
	}
	if !g.start("k") {
		t.Fatal("not retried after backoff elapsed")
	}
	g.finish("k", nil)
	if !g.start("k") {
		t.Fatal("success did not clear backoff")
	}
}

// A failed task re-tasked under a new ID is still the same certificate.
func TestRenewKey_PrefersFingerprint(t *testing.T) {
	a := agentclient.RenewalTask{TaskID: "1", Fingerprint: "ff"}
	b := agentclient.RenewalTask{TaskID: "2", Fingerprint: "ff"}
	if renewKey(a) != renewKey(b) {
		t.Fatal("same fingerprint, different keys")
	}
	if renewKey(agentclient.RenewalTask{TaskID: "1"}) == renewKey(agentclient.RenewalTask{TaskID: "2"}) {
		t.Fatal("distinct IDs without fingerprint share a key")
	}
}

func TestDispatchRenewals_FailureBacksOffAndSkipsNonRenew(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	g := testGuard(&clock)
	var runs atomic.Int32
	done := make(chan struct{}, 4)
	run := func(agentclient.RenewalTask) error { runs.Add(1); done <- struct{}{}; return errors.New("x") }
	renew := agentclient.RenewalTask{TaskID: "t", Fingerprint: "ab", Action: "renew"}
	other := agentclient.RenewalTask{TaskID: "o", Fingerprint: "cd", Action: "revoke"}

	g.dispatchRenewals([]agentclient.RenewalTask{renew, other}, run)
	<-done
	waitFree(t, g)
	g.dispatchRenewals([]agentclient.RenewalTask{renew}, run) // inside the backoff
	time.Sleep(20 * time.Millisecond)
	if runs.Load() != 1 {
		t.Fatalf("runs=%d, want 1 (backoff + non-renew skipped)", runs.Load())
	}
	clock = clock.Add(61 * time.Second)
	g.dispatchRenewals([]agentclient.RenewalTask{renew}, run)
	<-done
	if runs.Load() != 2 {
		t.Fatalf("runs=%d, want 2 after backoff", runs.Load())
	}
}

func waitFree(t *testing.T, g *renewGuard) {
	t.Helper()
	for range 200 {
		g.mu.Lock()
		r := g.running
		g.mu.Unlock()
		if !r {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("slot never released")
}
