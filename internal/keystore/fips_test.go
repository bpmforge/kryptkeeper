// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"crypto/fips140"
	"strings"
	"testing"
)

// W9-11: FIPS posture is enforced, not claimed. These tests run in both
// normal and GODEBUG=fips140=on builds; assertions branch on the real
// module state so CI can exercise either posture.

func TestFIPSPostureReportsLiveModuleState(t *testing.T) {
	p := FIPSPosture()
	if p.Mode140_3 != fips140.Enabled() {
		t.Fatalf("posture mode %v must mirror crypto/fips140.Enabled() %v", p.Mode140_3, fips140.Enabled())
	}
	if p.Enforced != fips140.Enforced() {
		t.Fatalf("posture enforcement must mirror the module state")
	}
	if p.Mode140_3 && p.ModuleVersion == "" {
		t.Fatal("FIPS mode on but no module version reported")
	}
	if p.Mode140_3 && !p.RootHSMRequired {
		t.Fatal("FIPS mode must imply NFR-011 root custody")
	}
}

func TestCheckFIPSAlgorithm(t *testing.T) {
	if fips140.Enabled() {
		// In FIPS mode: approved families pass, hybrids are refused.
		for _, algo := range []Algorithm{RSA4096, ECDSAP256, Ed25519, MLDSA65} {
			if err := CheckFIPSAlgorithm(algo); err != nil {
				t.Errorf("%s: approved family refused in FIPS mode: %v", algo, err)
			}
		}
		for _, algo := range []Algorithm{HybridECDSAP256MLDSA65, HybridECDSAP384MLDSA87} {
			err := CheckFIPSAlgorithm(algo)
			if err == nil {
				t.Errorf("%s: hybrid composite must be refused in FIPS mode", algo)
				continue
			}
			if !strings.Contains(err.Error(), "FIPS_POSTURE") {
				t.Errorf("%s: refusal must cite the posture doc, got: %v", algo, err)
			}
		}
		return
	}
	// Outside FIPS mode the check is a no-op — posture is a deployment
	// choice, not a universal restriction.
	for _, algo := range []Algorithm{RSA4096, HybridECDSAP256MLDSA65} {
		if err := CheckFIPSAlgorithm(algo); err != nil {
			t.Errorf("%s: non-FIPS build must not restrict algorithms: %v", algo, err)
		}
	}
	// The family classification itself is testable regardless of mode.
	for algo, want := range map[Algorithm]bool{
		RSA2048: true, RSA4096: true, ECDSAP256: true, ECDSAP384: true,
		Ed25519: true, MLDSA44: true, MLDSA65: true, MLDSA87: true,
		HybridECDSAP256MLDSA65: false, HybridECDSAP384MLDSA87: false,
		Algorithm("DES"): false,
	} {
		if got := fipsApprovedFamily(algo); got != want {
			t.Errorf("fipsApprovedFamily(%s) = %v, want %v", algo, got, want)
		}
	}
}

func TestRootKeyCustodyEnforcedNotClaimed(t *testing.T) {
	// NFR-011, explicitly switched on.
	t.Setenv("KRYPTKEEPER_FIPS_ROOT_HSM", "true")

	for _, backend := range []string{"software", "", "vault"} {
		err := CheckRootKeyCustody(backend)
		if err == nil {
			t.Errorf("backend %q must be refused as root custody under FIPS posture", backend)
			continue
		}
		if !strings.Contains(err.Error(), "NFR-011") {
			t.Errorf("refusal must name NFR-011, got: %v", err)
		}
	}
	for _, backend := range []string{"pkcs11", "cloudkms"} {
		if err := CheckRootKeyCustody(backend); err != nil {
			t.Errorf("backend %q is valid custody, got refusal: %v", backend, err)
		}
	}
}

func TestRootKeyCustodyOffByDefault(t *testing.T) {
	t.Setenv("KRYPTKEEPER_FIPS_ROOT_HSM", "")
	if fips140.Enabled() {
		t.Skip("FIPS mode implies custody; the off-by-default case needs a non-FIPS run")
	}
	if err := CheckRootKeyCustody("software"); err != nil {
		t.Fatalf("without FIPS posture the software backend must remain allowed: %v", err)
	}
}
