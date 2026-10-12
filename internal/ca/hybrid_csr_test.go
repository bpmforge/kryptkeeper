// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"kryptkeeper/internal/keystore"
)

func newTestHybridKeyPair(t *testing.T, algo keystore.Algorithm) keystore.HybridKeyPair {
	t.Helper()
	store, err := keystore.NewSoftwareStore(t.TempDir(), []byte("test-passphrase-not-for-production"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if _, err := store.GenerateKey("hybrid-csr-test-key", algo); err != nil {
		t.Fatalf("generate hybrid key: %v", err)
	}
	pair, err := store.LoadHybridKeyPair("hybrid-csr-test-key")
	if err != nil {
		t.Fatalf("load hybrid key pair: %v", err)
	}
	return pair
}

func TestCreateAndParseCertificateRequestHybrid_RoundTrip(t *testing.T) {
	for _, algo := range []keystore.Algorithm{keystore.HybridECDSAP256MLDSA65, keystore.HybridECDSAP384MLDSA87} {
		t.Run(string(algo), func(t *testing.T) {
			pair := newTestHybridKeyPair(t, algo)

			wantDNS := []string{"hybrid-leaf.example.com"}
			der, err := CreateCertificateRequestHybrid(pkix.Name{CommonName: "hybrid-leaf.example.com"}, wantDNS, nil, pair.Primary, pair.Secondary, algo)
			if err != nil {
				t.Fatalf("CreateCertificateRequestHybrid: %v", err)
			}

			parsed, err := ParseCertificateRequestHybrid(der)
			if err != nil {
				t.Fatalf("ParseCertificateRequestHybrid: %v", err)
			}
			if parsed.Subject.CommonName != "hybrid-leaf.example.com" {
				t.Errorf("CommonName = %q, want hybrid-leaf.example.com", parsed.Subject.CommonName)
			}
			if parsed.Algorithm != algo {
				t.Errorf("Algorithm = %s, want %s", parsed.Algorithm, algo)
			}
			if len(parsed.DNSNames) != 1 || parsed.DNSNames[0] != "hybrid-leaf.example.com" {
				t.Errorf("DNSNames = %v, want [hybrid-leaf.example.com]", parsed.DNSNames)
			}

			wantPrimaryBytes, err := x509.MarshalPKIXPublicKey(pair.Primary.Public())
			if err != nil {
				t.Fatalf("marshal want primary pub: %v", err)
			}
			gotPrimaryBytes, err := x509.MarshalPKIXPublicKey(parsed.PrimaryPublicKey)
			if err != nil {
				t.Fatalf("marshal got primary pub: %v", err)
			}
			if string(wantPrimaryBytes) != string(gotPrimaryBytes) {
				t.Error("PrimaryPublicKey mismatch after round-trip")
			}

			wantAltBytes, err := pair.Secondary.Public().(keystore.MLDSAPublicKey).MarshalBinary()
			if err != nil {
				t.Fatalf("marshal want alt pub: %v", err)
			}
			gotAltBytes, err := parsed.AltPublicKey.MarshalBinary()
			if err != nil {
				t.Fatalf("marshal got alt pub: %v", err)
			}
			if string(wantAltBytes) != string(gotAltBytes) {
				t.Error("AltPublicKey mismatch after round-trip")
			}
		})
	}
}

func TestParseCertificateRequestHybrid_TamperedPrimarySignatureRejected(t *testing.T) {
	pair := newTestHybridKeyPair(t, keystore.HybridECDSAP256MLDSA65)
	der, err := CreateCertificateRequestHybrid(pkix.Name{CommonName: "tamper-primary.example.com"}, nil, nil, pair.Primary, pair.Secondary, keystore.HybridECDSAP256MLDSA65)
	if err != nil {
		t.Fatalf("CreateCertificateRequestHybrid: %v", err)
	}

	tampered := append([]byte(nil), der...)
	// Flip the last byte of the DER -- the outer Signature field is encoded
	// last, so this reliably corrupts the primary signature bytes.
	tampered[len(tampered)-1] ^= 0xFF
	if _, err := ParseCertificateRequestHybrid(tampered); err == nil {
		t.Fatal("expected tampered primary signature to fail verification, got nil error")
	}
}

func TestParseCertificateRequestHybrid_MissingAltComponentsRejected(t *testing.T) {
	// A CSR with no alt-key/alt-signature at all (e.g. an ML-DSA-only CSR
	// mistakenly fed to the hybrid parser) must be rejected, not silently
	// treated as a valid classical-only result -- G-67's exact failure mode.
	keys, keyID := newTestMLDSASigner(t, keystore.MLDSA65)
	signer, err := keys.Signer(keyID)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	der, err := CreateCertificateRequestMLDSA(pkix.Name{CommonName: "not-hybrid.example.com"}, nil, nil, signer, keystore.MLDSA65)
	if err != nil {
		t.Fatalf("CreateCertificateRequestMLDSA: %v", err)
	}
	if _, err := ParseCertificateRequestHybrid(der); err == nil {
		t.Fatal("expected an ML-DSA-only CSR to be rejected by the hybrid parser, got nil error")
	}
}
