// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"strings"
	"testing"
	"time"
)

// W16-05: DORA/NIS2 control mappings — framework selection, status
// from live posture, and flow through the evidence report.

func cleanInventory() []CertificateItem {
	future := time.Now().Add(90 * 24 * time.Hour).Format(time.RFC3339)
	return []CertificateItem{
		{FingerprintSHA256: "a", CommonName: "a.example.com", OwnerTeam: "web", ValidUntil: future},
		{FingerprintSHA256: "b", CommonName: "b.example.com", OwnerTeam: "api", ValidUntil: future},
	}
}

func controlIDs(cs []ComplianceControl) map[string]ComplianceControl {
	m := map[string]ComplianceControl{}
	for _, c := range cs {
		m[c.ID] = c
	}
	return m
}

func TestDoraNIS2FrameworkSelection(t *testing.T) {
	inv := cleanInventory()
	now := time.Now()

	dora := doraNIS2Controls(inv, nil, "dora", now)
	if len(dora) != 3 {
		t.Fatalf("dora must yield exactly 3 controls, got %d", len(dora))
	}
	for _, c := range dora {
		if !strings.HasPrefix(c.ID, "DORA-") {
			t.Fatalf("dora selector must not emit %s", c.ID)
		}
	}

	nis2 := doraNIS2Controls(inv, nil, "nis2", now)
	if len(nis2) != 3 {
		t.Fatalf("nis2 must yield 3 controls, got %d", len(nis2))
	}
	for _, c := range nis2 {
		if !strings.HasPrefix(c.ID, "NIS2-") {
			t.Fatalf("nis2 selector must not emit %s", c.ID)
		}
	}

	all := doraNIS2Controls(inv, nil, "all", now)
	if len(all) != 6 {
		t.Fatalf("all must yield 6 controls, got %d", len(all))
	}

	none := doraNIS2Controls(inv, nil, "pci", now)
	if len(none) != 0 {
		t.Fatalf("an unrelated framework must yield no DORA/NIS2 controls, got %d", len(none))
	}
}

func TestDoraNIS2CleanInventoryPasses(t *testing.T) {
	for _, c := range doraNIS2Controls(cleanInventory(), nil, "all", time.Now()) {
		if c.Status != "pass" {
			t.Fatalf("clean inventory should pass %s, got %q", c.ID, c.Status)
		}
	}
}

func TestDoraNIS2WeakKeyFailsCryptoControl(t *testing.T) {
	inv := cleanInventory()
	inv = append(inv, CertificateItem{
		FingerprintSHA256: "weak", CommonName: "legacy.example.com",
		OwnerTeam: "web", ValidUntil: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		RiskFlags: []string{"WEAK_RSA_KEY"},
	})
	byID := controlIDs(doraNIS2Controls(inv, nil, "all", time.Now()))
	if byID["DORA-Art9"].Status != "fail" {
		t.Fatalf("DORA-Art9 must fail with a weak-key cert: %+v", byID["DORA-Art9"])
	}
	if byID["DORA-Art9"].Remediation == "" {
		t.Fatal("a failing crypto control must carry remediation")
	}
	if byID["NIS2-Art21-2h"].Status != "fail" {
		t.Fatalf("NIS2-Art21-2h must fail with weak crypto: %+v", byID["NIS2-Art21-2h"])
	}
}

func TestDoraNIS2FlowsThroughEvidenceReport(t *testing.T) {
	report := computeComplianceEvidence(cleanInventory(), nil, "all")
	found := false
	for _, c := range report.Controls {
		if c.ID == "NIS2-Art23" {
			found = true
		}
	}
	if !found {
		t.Fatal("DORA/NIS2 controls must flow into the compliance evidence report")
	}
	// The summary tally must fold them in.
	if report.Summary.Pass+report.Summary.Warn+report.Summary.Fail != len(report.Controls) {
		t.Fatal("summary must tally every control including the EU ones")
	}
}

// Review fix (concurrency challenger #5): an empty inventory must be
// consistent — NIS2-Art23 no longer fails when there are zero certs
// (nothing to report on), matching DORA's empty-passes convention.
func TestDoraNIS2EmptyEstateConsistent(t *testing.T) {
	byID := controlIDs(doraNIS2Controls(nil, nil, "all", time.Now()))
	for _, id := range []string{"DORA-Art10", "DORA-Art6", "NIS2-Art23"} {
		if byID[id].Status == "fail" {
			t.Fatalf("%s must not fail on an empty inventory: %q", id, byID[id].Status)
		}
	}
}
