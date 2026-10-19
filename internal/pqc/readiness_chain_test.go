// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package pqc

import "testing"

// W31-02 (D-104/D-105): leaf-only certificates must never be counted as
// quantum-safe by the tally, however many of them there are.
func TestTally_LeafOnlyNeverCountsAsQuantumSafe(t *testing.T) {
	var tally ReadinessTally
	for i := 0; i < 10; i++ {
		tally.Add(ReadinessLeafOnly)
	}
	tally.Finalize(10)
	if tally.QuantumSafe != 0 || tally.QuantumSafePercent != 0 {
		t.Errorf("leaf-only fleet counted as quantum safe: %+v", tally)
	}
	if tally.QuantumSafeLeafOnly != 10 || tally.PQCScorePercent != 100 {
		t.Errorf("leaf-only fleet tally wrong: %+v", tally)
	}
}
