// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ratelimit

import (
	"fmt"
	"testing"
	"time"
)

func fullLimiter(now time.Time) *Limiter {
	l := New(5, time.Hour)
	for i := 0; i < maxKeys; i++ {
		l.AllowAt(fmt.Sprintf("live-%d", i), now)
	}
	return l
}

// RC2-N-01: at the cap, a stream of new keys must not rescan the whole map per
// call (that serialised every limiter-protected route under the mutex).
func BenchmarkAllowAtCapacityNewKeys(b *testing.B) {
	now := time.Now()
	l := fullLimiter(now)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.AllowAt(fmt.Sprintf("new-%d", i), now.Add(time.Second))
	}
}

func TestLimiter_FullMapSweepsAtMostOncePerWindow(t *testing.T) {
	now := time.Now()
	l := fullLimiter(now)
	l.lastSweep = now // a sweep just ran; every key is still live
	start := time.Now()
	const n = 2000
	for i := 0; i < n; i++ {
		l.AllowAt(fmt.Sprintf("new-%d", i), now.Add(time.Second))
	}
	if got := len(l.buckets); got > maxKeys {
		t.Fatalf("map grew to %d, cap is %d", got, maxKeys)
	}
	// A per-call O(maxKeys) sweep costs ~0.6 ms each (about 1.3 s for 2000);
	// an amortised O(1) eviction is orders of magnitude below this bound.
	if elapsed := time.Since(start); elapsed > 400*time.Millisecond {
		t.Fatalf("%d new-key calls on a full map took %v; the full-map sweep is not amortised", n, elapsed)
	}
}

func TestLimiter_FullMapStillSweepsOncePerWindow(t *testing.T) {
	now := time.Now()
	l := fullLimiter(now)
	// Every live key ages out; the first new key after the window sweeps them.
	l.AllowAt("fresh", now.Add(2*time.Hour))
	if got := len(l.buckets); got != 1 {
		t.Fatalf("aged-out keys not swept at capacity: %d resident, want 1", got)
	}
}
