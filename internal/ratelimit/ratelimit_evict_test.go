// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ratelimit

import (
	"fmt"
	"testing"
	"time"
)

func TestLimiter_EvictsIdleKeys(t *testing.T) {
	l := New(3, time.Minute)
	now := time.Now()
	for i := 0; i < 1000; i++ {
		l.AllowAt(fmt.Sprintf("idle-%d", i), now)
	}
	if got := len(l.buckets); got != 1000 {
		t.Fatalf("setup: %d keys", got)
	}
	// A new key after the window triggers the sweep; none of the idle keys
	// is ever seen again.
	l.AllowAt("fresh", now.Add(2*time.Minute))
	if got := len(l.buckets); got != 1 {
		t.Fatalf("idle keys not evicted: %d resident, want 1", got)
	}
}

func TestLimiter_EvictionKeepsLiveKeysLimited(t *testing.T) {
	l := New(2, time.Minute)
	now := time.Now()
	l.AllowAt("busy", now)
	l.AllowAt("busy", now.Add(30*time.Second))
	l.AllowAt("idle", now)
	later := now.Add(61 * time.Second) // idle aged out, busy's second hit has not
	l.AllowAt("trigger", later)
	if _, ok := l.buckets["idle"]; ok {
		t.Fatal("idle key survived the sweep")
	}
	if !l.AllowAt("busy", later) {
		t.Fatal("busy's first hit aged out, one slot should be free")
	}
	if l.AllowAt("busy", later) {
		t.Fatal("busy must still be limited after the sweep")
	}
}

func TestLimiter_MapIsCapped(t *testing.T) {
	l := New(5, time.Hour)
	now := time.Now()
	for i := 0; i < maxKeys+500; i++ {
		l.AllowAt(fmt.Sprintf("k-%d", i), now)
	}
	if got := len(l.buckets); got > maxKeys {
		t.Fatalf("map grew to %d, cap is %d", got, maxKeys)
	}
}
