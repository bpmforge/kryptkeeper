// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import "testing"

func TestIsRSAAlgorithm(t *testing.T) {
	for alg, want := range map[string]bool{
		"RSA": true, "rsa": true, "RSA-3072": true, " RSA-2048 ": true, "RSA2048": true, "RSASSA-PSS": true,
		"ECDSA-P256": false, "EC": false, "Ed25519": false, "ML-DSA-65": false, "": false,
	} {
		if got := IsRSAAlgorithm(alg); got != want {
			t.Errorf("IsRSAAlgorithm(%q) = %v, want %v", alg, got, want)
		}
	}
}
