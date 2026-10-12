// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package pqc

import (
	"testing"
	"time"
)

// W16-03: crypto-agility orchestration — policy matching, wave
// derivation, progress, and Overdue.

func agilityInventory() []CertRecord {
	return []CertRecord{
		{Fingerprint: "a", CommonName: "test.example.com", Algorithm: "RSA", KeySize: 2048},
		{Fingerprint: "b", CommonName: "shop.example.com", Algorithm: "RSA", KeySize: 2048},
		{Fingerprint: "c", CommonName: "vault.internal", Algorithm: "RSA", KeySize: 4096},
		{Fingerprint: "d", CommonName: "api.example.com", Algorithm: "ECDSA", KeySize: 256},
	}
}

func rsa2048Policy() DeprecationPolicy {
	return DeprecationPolicy{
		Name:       "RSA-2048 disallowed (NIST 800-131A, 2030)",
		Algorithms: []string{"RSA"}, MaxKeyBits: 2048,
		Deadline: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

func TestPolicyMatchesRespectsKeySize(t *testing.T) {
	p := rsa2048Policy()
	inv := agilityInventory()
	if !p.Matches(inv[0]) || !p.Matches(inv[1]) {
		t.Fatal("RSA-2048 certs must match an RSA<=2048 policy")
	}
	if p.Matches(inv[2]) {
		t.Fatal("RSA-4096 must NOT match an RSA<=2048 policy")
	}
	if p.Matches(inv[3]) {
		t.Fatal("ECDSA must NOT match an RSA policy")
	}
}

func TestDeriveAgilityRoadmapTiers(t *testing.T) {
	rm := DeriveAgilityRoadmap(agilityInventory(), rsa2048Policy(), time.Now())
	if rm.TotalMatched != 2 {
		t.Fatalf("only the two RSA-2048 certs match: %d", rm.TotalMatched)
	}
	// test.example.com → Test; shop.example.com → Customer-Facing.
	if len(rm.ByWave["Test"]) != 1 || rm.ByWave["Test"][0].Fingerprint != "a" {
		t.Fatalf("test cert must land in Test: %+v", rm.ByWave["Test"])
	}
	if len(rm.ByWave["Customer-Facing"]) != 1 || rm.ByWave["Customer-Facing"][0].Fingerprint != "b" {
		t.Fatalf("public cert must land in Customer-Facing: %+v", rm.ByWave["Customer-Facing"])
	}
	// Each matched item carries the policy deadline.
	if !rm.ByWave["Test"][0].Deadline.Equal(rsa2048Policy().Deadline) {
		t.Fatal("item must carry the policy deadline")
	}
}

func TestProgressAndOverdue(t *testing.T) {
	inv := agilityInventory()
	pol := rsa2048Policy()
	// Before the deadline: 2 of 4 remain → 50% migrated, not overdue.
	pre := Progress(inv, pol, time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC))
	if pre.MatchedRemaining != 2 || pre.PercentMigrated != 50 || pre.Overdue {
		t.Fatalf("pre-deadline progress: %+v", pre)
	}
	// After the deadline with matches remaining: overdue.
	post := Progress(inv, pol, time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC))
	if !post.Overdue {
		t.Fatalf("past-deadline with remaining matches must be overdue: %+v", post)
	}
	// A fully-migrated inventory is never overdue.
	migrated := []CertRecord{{Fingerprint: "x", CommonName: "a.example.com", Algorithm: "ML-DSA-65"}}
	done := Progress(migrated, pol, time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC))
	if done.Overdue || done.PercentMigrated != 100 {
		t.Fatalf("migrated inventory must be 100%% and not overdue: %+v", done)
	}
}

func TestPolicyAlgorithmOnlyMatchesAnySize(t *testing.T) {
	// No MaxKeyBits: an "all ECDSA" policy matches regardless of size.
	p := DeprecationPolicy{Name: "retire ECDSA", Algorithms: []string{"ECDSA"}}
	if !p.Matches(CertRecord{Algorithm: "ECDSA", KeySize: 256}) {
		t.Fatal("algorithm-only policy must match any key size")
	}
}
