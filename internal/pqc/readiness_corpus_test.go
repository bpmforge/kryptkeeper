// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package pqc

import (
	"fmt"
	"testing"
	"time"
)

// corpus500 mirrors the W31-01 seeded corpus in the bootstrap tests: 260
// vulnerable, 70 migration_ready, 90 quantum_safe, 60 leaf-only and 20
// not_applicable (Ed25519 counts as classical, unknown OIDs as not_applicable).
func corpus500() []CertRecord {
	var certs []CertRecord
	add := func(class, readiness string, n int) {
		for i := 0; i < n; i++ {
			certs = append(certs, CertRecord{Fingerprint: fmt.Sprintf("%s-%d", class, i), PQCReadiness: readiness})
		}
	}
	add("rsa2048-long", ReadinessVulnerable, 80)
	add("rsa2048-short", ReadinessMigrReady, 30)
	add("rsa4096-long", ReadinessVulnerable, 60)
	add("p256-long", ReadinessVulnerable, 40)
	add("p256-short", ReadinessMigrReady, 40)
	add("p384-long", ReadinessVulnerable, 50)
	add("ed25519-long", ReadinessVulnerable, 30)
	add("mldsa44", ReadinessQuantumSafe, 30)
	add("mldsa65", ReadinessQuantumSafe, 30)
	add("mldsa87", ReadinessQuantumSafe, 30)
	add("mldsa65-ecdsa-ca", ReadinessLeafOnly, 20)
	add("hybrid", ReadinessLeafOnly, 40)
	add("unknown-oid", "not_applicable", 20)
	return certs
}

func TestReadinessCorpus_500(t *testing.T) {
	certs := corpus500()
	if len(certs) != 500 {
		t.Fatalf("corpus size = %d, want 500", len(certs))
	}

	var tally ReadinessTally
	for _, c := range certs {
		tally.Add(c.PQCReadiness)
	}
	tally.Finalize(len(certs))

	rm := NewPlanner(time.Time{}).GenerateRoadmap(certs)

	for name, got := range map[string]ReadinessTally{
		"tally": tally,
		"roadmap": {
			QuantumSafe: rm.QuantumSafe, QuantumSafeLeafOnly: rm.QuantumSafeLeafOnly, MigrationReady: rm.MigrationReady,
			Vulnerable: rm.Vulnerable, NotApplicable: rm.NotApplicable,
			QuantumSafePercent: rm.QuantumSafePercent, PQCScorePercent: rm.PQCScorePercent,
		},
	} {
		if got.Vulnerable != 260 || got.MigrationReady != 70 || got.QuantumSafe != 90 ||
			got.QuantumSafeLeafOnly != 60 || got.NotApplicable != 20 {
			t.Errorf("%s counts: %+v", name, got)
		}
		if got.QuantumSafePercent != 18 || got.PQCScorePercent != 44 {
			t.Errorf("%s percents = %d/%d, want 18/44", name, got.QuantumSafePercent, got.PQCScorePercent)
		}
	}
	if rm.TotalCerts != 500 {
		t.Errorf("roadmap total = %d, want 500", rm.TotalCerts)
	}
}

func TestReadinessCorpus_EmptyInventory(t *testing.T) {
	rm := NewPlanner(time.Time{}).GenerateRoadmap(nil)
	if rm.TotalCerts != 0 || rm.QuantumSafePercent != 0 || rm.PQCScorePercent != 0 {
		t.Errorf("empty roadmap = %+v", rm)
	}
	var tally ReadinessTally
	tally.Finalize(0)
	if tally.QuantumSafePercent != 0 || tally.PQCScorePercent != 0 {
		t.Errorf("empty tally = %+v", tally)
	}
}

// synthetic100k repeats the 500-cert corpus 200 times with unique fingerprints
// and a validity window so the planner exercises its date logic.
func synthetic100k() []CertRecord {
	base := corpus500()
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	certs := make([]CertRecord, 0, 100_000)
	for r := 0; r < 200; r++ {
		for _, c := range base {
			c.Fingerprint = fmt.Sprintf("%s-r%d", c.Fingerprint, r)
			c.ValidFrom = from
			c.ValidUntil = from.AddDate(0, 0, 90+r)
			certs = append(certs, c)
		}
	}
	return certs
}

func BenchmarkRoadmap100k(b *testing.B) {
	certs := synthetic100k()
	p := NewPlanner(time.Time{})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rm := p.GenerateRoadmap(certs)
		if rm.TotalCerts != 100_000 {
			b.Fatalf("total = %d", rm.TotalCerts)
		}
	}
}

func TestRoadmap100kUnder3s(t *testing.T) {
	if testing.Short() {
		t.Skip("100k timing guard skipped in -short")
	}
	certs := synthetic100k()
	start := time.Now()
	rm := NewPlanner(time.Time{}).GenerateRoadmap(certs)
	var tally ReadinessTally
	for _, c := range certs {
		tally.Add(c.PQCReadiness)
	}
	tally.Finalize(len(certs))
	elapsed := time.Since(start)
	t.Logf("100k roadmap + tally: %s", elapsed)

	if rm.TotalCerts != 100_000 || rm.Vulnerable != 52_000 || tally.Vulnerable != 52_000 {
		t.Errorf("unexpected 100k counts: roadmap %+v tally %+v", rm.TotalCerts, tally)
	}
	if elapsed > 3*time.Second {
		t.Errorf("100k roadmap took %s, budget 3s", elapsed)
	}
}
