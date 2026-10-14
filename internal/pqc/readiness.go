// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package pqc

// Per-certificate PQC readiness values as stored on CertificateItem.
const (
	ReadinessQuantumSafe = "quantum_safe"
	// ReadinessLeafOnly (G-70/D-104): subject key is PQC but a classical
	// signature exists somewhere in the chain.
	ReadinessLeafOnly   = "quantum_safe_leaf_only"
	ReadinessMigrReady  = "migration_ready"
	ReadinessHybrid     = "hybrid_quantum_safe"
	ReadinessVulnerable = "vulnerable"
)

// ReadinessTally is the single definition of the fleet-level PQC numbers.
// Every report endpoint (crypto-posture, pqc-countdown, pqc-migration)
// aggregates through it so a label never carries two different values.
//
// Definitions:
//   - QuantumSafe: full chain PQC (leaf key and every signature to the root).
//   - QuantumSafeLeafOnly: PQC subject key under a classical chain; counted
//     separately, never as quantum-safe.
//   - MigrationReady: classical but short-lived, plus hybrid certificates
//     (their outer signature and chain are classical).
//   - Vulnerable: long-lived classical.
//   - NotApplicable: any other/unknown readiness value (never in the
//     migration roadmap's vulnerable bucket).
//
// QuantumSafePercent = QuantumSafe / total. PQCScorePercent ("PQC readiness")
// = (QuantumSafe + QuantumSafeLeafOnly + MigrationReady) / total. Both use
// integer division on the same total (all certificates in scope).
type ReadinessTally struct {
	QuantumSafe         int
	QuantumSafeLeafOnly int
	MigrationReady      int
	Vulnerable          int
	NotApplicable       int
	QuantumSafePercent  int
	PQCScorePercent     int
}

// Add counts one certificate's readiness value.
func (t *ReadinessTally) Add(readiness string) {
	switch readiness {
	case ReadinessQuantumSafe:
		t.QuantumSafe++
	case ReadinessLeafOnly:
		t.QuantumSafeLeafOnly++
	case ReadinessMigrReady, ReadinessHybrid:
		t.MigrationReady++
	case ReadinessVulnerable:
		t.Vulnerable++
	default:
		t.NotApplicable++
	}
}

// Finalize computes the percentages for total certificates in scope.
func (t *ReadinessTally) Finalize(total int) {
	if total <= 0 {
		t.QuantumSafePercent, t.PQCScorePercent = 0, 0
		return
	}
	t.QuantumSafePercent = t.QuantumSafe * 100 / total
	t.PQCScorePercent = (t.QuantumSafe + t.QuantumSafeLeafOnly + t.MigrationReady) * 100 / total
}
