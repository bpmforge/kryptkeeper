// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ctmonitor

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// W12-01: the provider-backed Inventory adapter — normalization, TTL
// caching, fail-closed errors, and end-to-end detection through it.

func TestNormalizeSerial(t *testing.T) {
	cases := map[string]string{
		"03:AB:cd:00": "3abcd00",
		"0003abCD":    "3abcd",
		"  ABCDEF ":   "abcdef",
		"00":          "0",
		"":            "0",
	}
	for in, want := range cases {
		if got := NormalizeSerial(in); got != want {
			t.Errorf("NormalizeSerial(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestProviderInventoryMatchesAcrossFormats(t *testing.T) {
	calls := 0
	inv := NewProviderInventory(func(context.Context) (map[string]struct{}, error) {
		calls++
		// Provider-side formatting: uppercase with colons and zeros.
		return map[string]struct{}{"00:AB:CD:EF": {}}, nil
	})
	// CT-side formatting: bare lowercase hex.
	known, err := inv.HasSerial(context.Background(), "abcdef")
	if err != nil || !known {
		t.Fatalf("formatting mismatch must still match: %v %v", known, err)
	}
	unknown, err := inv.HasSerial(context.Background(), "123456")
	if err != nil || unknown {
		t.Fatalf("unknown serial must be false: %v %v", unknown, err)
	}
	if calls != 1 {
		t.Fatalf("cache must serve the second lookup, got %d list calls", calls)
	}
}

func TestProviderInventoryTTLRefetch(t *testing.T) {
	calls := 0
	inv := NewProviderInventory(func(context.Context) (map[string]struct{}, error) {
		calls++
		return map[string]struct{}{}, nil
	})
	clock := time.Now()
	inv.now = func() time.Time { return clock }
	_, _ = inv.HasSerial(context.Background(), "aa")
	clock = clock.Add(10 * time.Minute) // past the 5m default TTL
	_, _ = inv.HasSerial(context.Background(), "aa")
	if calls != 2 {
		t.Fatalf("expired cache must refetch, got %d calls", calls)
	}
}

func TestProviderInventoryFailsClosed(t *testing.T) {
	inv := NewProviderInventory(func(context.Context) (map[string]struct{}, error) {
		return nil, fmt.Errorf("db down")
	})
	if _, err := inv.HasSerial(context.Background(), "aa"); err == nil {
		t.Fatal("an unreadable inventory must propagate the error, never report unknown")
	}
}

func TestMonitorDetectsThroughProviderAdapter(t *testing.T) {
	store := newTestStore(t)
	inv := NewProviderInventory(func(context.Context) (map[string]struct{}, error) {
		return map[string]struct{}{"00:AA:BB": {}}, nil // we issued this one
	})
	src := &fakeSource{entries: []CTEntry{
		{EntryID: "1", Serial: "aabb", CommonName: "ours.example.com", NotAfter: time.Now().Add(24 * time.Hour)},
		{EntryID: "2", Serial: "ffff", CommonName: "rogue.example.com", NotAfter: time.Now().Add(24 * time.Hour)},
	}}
	m, err := NewMonitor(src, inv, store, nil, []string{"example.com"})
	if err != nil {
		t.Fatalf("monitor: %v", err)
	}
	rep, err := m.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(rep.NewFindings) != 1 {
		t.Fatalf("expected exactly the rogue cert flagged, got %d findings", len(rep.NewFindings))
	}
	findings, err := store.List(context.Background(), "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(findings) != 1 || findings[0].CommonName != "rogue.example.com" {
		t.Fatalf("wrong finding persisted: %+v", findings)
	}
}
