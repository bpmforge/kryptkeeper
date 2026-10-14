// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package pqc

import (
	"testing"
	"time"
)

// mixedFixture is 40 certs: 5 full-chain PQC, 5 ML-DSA leaves under a
// classical CA (leaf-only), 4 hybrid, 16 short-lived classical, 8
// long-lived classical, 2 not-applicable. The bootstrap report tests
// pin the same numbers.
func mixedFixture() []CertRecord {
	var certs []CertRecord
	add := func(n int, readiness string) {
		for i := 0; i < n; i++ {
			certs = append(certs, CertRecord{Fingerprint: readiness + string(rune('a'+i)), PQCReadiness: readiness})
		}
	}
	add(5, ReadinessQuantumSafe)
	add(5, ReadinessLeafOnly)
	add(4, ReadinessHybrid)
	add(16, ReadinessMigrReady)
	add(8, ReadinessVulnerable)
	add(2, "not_applicable")
	return certs
}

func TestReadinessTallyMixedFixture(t *testing.T) {
	var tally ReadinessTally
	certs := mixedFixture()
	for _, c := range certs {
		tally.Add(c.PQCReadiness)
	}
	tally.Finalize(len(certs))

	if tally.QuantumSafe != 5 || tally.QuantumSafeLeafOnly != 5 || tally.MigrationReady != 20 ||
		tally.Vulnerable != 8 || tally.NotApplicable != 2 {
		t.Fatalf("unexpected counts: %+v", tally)
	}
	if tally.QuantumSafePercent != 12 { // 5/40: leaf-only is NOT quantum-safe
		t.Errorf("quantum_safe_percent = %d, want 12", tally.QuantumSafePercent)
	}
	if tally.PQCScorePercent != 75 { // (5+5+20)/40
		t.Errorf("pqc_score_percent = %d, want 75", tally.PQCScorePercent)
	}
}

func TestReadinessTallyEmpty(t *testing.T) {
	var tally ReadinessTally
	tally.Finalize(0)
	if tally.QuantumSafePercent != 0 || tally.PQCScorePercent != 0 {
		t.Errorf("empty tally = %+v", tally)
	}
}

// The roadmap endpoint must report the same numbers the posture/countdown
// reports derive from the same inventory.
func TestRoadmapMatchesTallyOnMixedFixture(t *testing.T) {
	rm := NewPlanner(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)).GenerateRoadmap(mixedFixture())

	if rm.QuantumSafe != 5 || rm.QuantumSafeLeafOnly != 5 || rm.MigrationReady != 20 ||
		rm.Vulnerable != 8 || rm.NotApplicable != 2 {
		t.Fatalf("unexpected roadmap counts: %+v", rm)
	}
	if rm.QuantumSafePercent != 12 || rm.PQCScorePercent != 75 {
		t.Errorf("percents = %d/%d, want 12/75", rm.QuantumSafePercent, rm.PQCScorePercent)
	}
}
