// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package sshkeys

import (
	"testing"
	"time"
)

func TestNewInventory(t *testing.T) {
	inv := NewInventory()
	if inv == nil {
		t.Fatal("expected non-nil inventory")
	}
	if len(inv.List()) != 0 {
		t.Error("expected empty inventory")
	}
}

func TestInventoryAddAndList(t *testing.T) {
	inv := NewInventory()
	key := SSHKey{
		Fingerprint: "SHA256:abc123",
		Host:        "server.example.com",
		KeyType:     Ed25519,
	}
	inv.Add(key)
	keys := inv.List()
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if keys[0].Fingerprint != "SHA256:abc123" {
		t.Errorf("unexpected fingerprint %q", keys[0].Fingerprint)
	}
}

func TestInventoryStaleKeys(t *testing.T) {
	inv := NewInventory()
	old := time.Now().Add(-200 * 24 * time.Hour)
	// LastRotated nil → stale
	inv.Add(SSHKey{Fingerprint: "stale", Host: "old.example.com", KeyType: RSA})
	// LastRotated recent → not stale
	fresh := time.Now()
	inv.Add(SSHKey{Fingerprint: "fresh", Host: "new.example.com", KeyType: Ed25519, LastRotated: &fresh})
	_ = old
	stale := inv.StaleKeys(time.Now())
	if len(stale) != 1 {
		t.Errorf("expected 1 stale key, got %d", len(stale))
	}
	if stale[0].Fingerprint != "stale" {
		t.Errorf("unexpected stale key %q", stale[0].Fingerprint)
	}
}

func TestInventoryStats(t *testing.T) {
	inv := NewInventory()
	now := time.Now()
	recent := now.Add(-10 * 24 * time.Hour)
	inv.Add(SSHKey{Fingerprint: "k1", Host: "h1", KeyType: Ed25519, LastRotated: &recent})
	inv.Add(SSHKey{Fingerprint: "k2", Host: "h2", KeyType: RSA}) // nil LastRotated → stale
	stats := inv.Stats(now)
	if stats.Total != 2 {
		t.Errorf("expected 2 total, got %d", stats.Total)
	}
	if stats.Stale != 1 {
		t.Errorf("expected 1 stale, got %d", stats.Stale)
	}
}

func TestIsStale(t *testing.T) {
	// nil LastRotated → stale
	k := SSHKey{}
	if !k.IsStale(time.Now()) {
		t.Error("expected key with no rotation date to be stale")
	}
	// Recent rotation → not stale
	recent := time.Now().Add(-10 * 24 * time.Hour)
	k2 := SSHKey{LastRotated: &recent}
	if k2.IsStale(time.Now()) {
		t.Error("expected recently rotated key to not be stale")
	}
}
