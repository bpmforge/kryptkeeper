// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
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
		approved := []Algorithm{RSA4096, ECDSAP256, Ed25519}
		if !fips140.Enforced() {
			// ML-DSA is out-of-module: allowed in "on", refused in "only"
			// (TestFIPSOnlyRefusesMLDSA).
			approved = append(approved, MLDSA65)
		}
		for _, algo := range approved {
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
		RSA2048: true, RSA3072: true, RSA4096: true, ECDSAP256: true, ECDSAP384: true,
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

// W23-31: scoped fips140=only coverage. The whole keystore suite cannot run
// under "only" (the software store's AES-GCM uses arbitrary IVs), so these
// tests use stdlib keys and the pure policy check.

func TestFIPSOnlyModeIsActiveWhenExpected(t *testing.T) {
	// Guards the CI job against going vacuously green with GODEBUG unset.
	if os.Getenv("KK_EXPECT_FIPS_ONLY") == "1" && !fips140.Enforced() {
		t.Fatal("KK_EXPECT_FIPS_ONLY=1 but crypto/fips140.Enforced() is false: GODEBUG=fips140=only is not in effect")
	}
}

func TestFIPSOnlyApprovedAlgorithms(t *testing.T) {
	if !fips140.Enforced() {
		t.Skip("needs GODEBUG=fips140=only")
	}
	cases := []struct {
		algo Algorithm
		gen  func() (crypto.Signer, error)
	}{
		{ECDSAP256, func() (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }},
		{ECDSAP384, func() (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P384(), rand.Reader) }},
		{RSA2048, func() (crypto.Signer, error) { return rsa.GenerateKey(rand.Reader, 2048) }},
		{RSA4096, func() (crypto.Signer, error) { return rsa.GenerateKey(rand.Reader, 4096) }},
	}
	for _, c := range cases {
		t.Run(string(c.algo), func(t *testing.T) {
			if err := CheckFIPSAlgorithm(c.algo); err != nil {
				t.Fatalf("approved algorithm refused: %v", err)
			}
			key, err := c.gen()
			if err != nil {
				t.Fatalf("generate: %v", err)
			}
			tmpl := &x509.Certificate{
				SerialNumber:          big.NewInt(1),
				Subject:               pkix.Name{CommonName: "fips-only " + string(c.algo)},
				NotBefore:             time.Now().Add(-time.Minute),
				NotAfter:              time.Now().Add(time.Hour),
				IsCA:                  true,
				BasicConstraintsValid: true,
				KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
			}
			der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
			if err != nil {
				t.Fatalf("self-sign: %v", err)
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if err := cert.CheckSignatureFrom(cert); err != nil {
				t.Fatalf("verify self-signature: %v", err)
			}
		})
	}
}

func TestFIPSOnlyRefusesMLDSA(t *testing.T) {
	if !fips140.Enforced() {
		t.Skip("needs GODEBUG=fips140=only")
	}
	for _, algo := range []Algorithm{MLDSA44, MLDSA65, MLDSA87} {
		err := CheckFIPSAlgorithm(algo)
		if err == nil {
			t.Errorf("%s: must be refused under fips140=only", algo)
			continue
		}
		if !strings.Contains(err.Error(), "FIPS_POSTURE.md") {
			t.Errorf("%s: refusal must name FIPS_POSTURE.md, got: %v", algo, err)
		}
	}
}
