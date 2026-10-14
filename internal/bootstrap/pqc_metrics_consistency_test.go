// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"fmt"
	"testing"
	"time"

	"kryptkeeper/internal/pqc"
)

// mixedPQCInventory is 40 certs: 5 full-chain PQC, 5 ML-DSA leaves under a
// classical CA (leaf-only), 4 hybrid, 16 short-lived classical, 8 long-lived
// classical, 2 not-applicable.
func mixedPQCInventory() []CertificateItem {
	var certs []CertificateItem
	add := func(n int, readiness string) {
		for i := 0; i < n; i++ {
			certs = append(certs, CertificateItem{
				FingerprintSHA256: fmt.Sprintf("%s-%d", readiness, i),
				PQCReadiness:      readiness,
				ValidUntil:        time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339),
			})
		}
	}
	add(5, "quantum_safe")
	add(5, "quantum_safe_leaf_only")
	add(4, "hybrid_quantum_safe")
	add(16, "migration_ready")
	add(8, "vulnerable")
	add(2, "not_applicable")
	return certs
}

// TestPQCMetricsConsistentAcrossReports pins the single definition: the
// crypto-posture, pqc-countdown and pqc-migration reports must agree on every
// shared label for the same inventory, and leaf-only is never quantum-safe.
func TestPQCMetricsConsistentAcrossReports(t *testing.T) {
	certs := mixedPQCInventory()
	posture := computeCryptoPostureReport(certs, nil).PQCReadiness
	countdown := computePQCCountdown(context.Background(), certs, nil, nil, time.Now().UTC(), nil)

	records := make([]pqc.CertRecord, 0, len(certs))
	for _, c := range certs {
		records = append(records, toPQCCertRecord(c))
	}
	roadmap := pqc.NewPlanner(time.Time{}).GenerateRoadmap(records)

	if posture.QuantumSafe != 5 || posture.QuantumSafeLeafOnly != 5 || posture.MigrationReady != 20 ||
		posture.Vulnerable != 8 || posture.NotApplicable != 2 {
		t.Fatalf("posture counts: %+v", posture)
	}
	if posture.QuantumSafePercent != 12 || posture.PQCScorePercent != 75 {
		t.Fatalf("posture percents: %+v", posture)
	}
	if countdown.QuantumSafe != posture.QuantumSafe || countdown.QuantumSafeLeafOnly != posture.QuantumSafeLeafOnly ||
		countdown.MigrationReady != posture.MigrationReady || countdown.Vulnerable != posture.Vulnerable ||
		countdown.PQCScorePercent != posture.PQCScorePercent || countdown.QuantumSafePercent != posture.QuantumSafePercent {
		t.Errorf("countdown %+v disagrees with posture %+v", countdown, posture)
	}
	if roadmap.QuantumSafe != posture.QuantumSafe || roadmap.QuantumSafeLeafOnly != posture.QuantumSafeLeafOnly ||
		roadmap.MigrationReady != posture.MigrationReady || roadmap.Vulnerable != posture.Vulnerable ||
		roadmap.PQCScorePercent != posture.PQCScorePercent || roadmap.QuantumSafePercent != posture.QuantumSafePercent {
		t.Errorf("roadmap %+v disagrees with posture %+v", roadmap, posture)
	}
}

// The observed hub: ML-DSA leaves under an ECDSA CA must show 0% quantum-safe.
func TestPQCMetrics_LeafOnlyIsNotQuantumSafe(t *testing.T) {
	var certs []CertificateItem
	for i := 0; i < 5; i++ {
		certs = append(certs, CertificateItem{FingerprintSHA256: fmt.Sprintf("l%d", i), PQCReadiness: "quantum_safe_leaf_only"})
	}
	p := computeCryptoPostureReport(certs, nil).PQCReadiness
	if p.QuantumSafe != 0 || p.QuantumSafePercent != 0 || p.QuantumSafeLeafOnly != 5 || p.PQCScorePercent != 100 {
		t.Errorf("leaf-only fleet: %+v", p)
	}
}
