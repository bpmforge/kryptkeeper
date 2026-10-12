// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/x509/pkix"
	"testing"
	"time"

	"kryptkeeper/internal/keystore"
)

// TestIssueCertificateFromHybridCSR_AnyCAIssuesHybridLeaf proves acceptance
// #2: a CA of any key type can issue a hybrid leaf. Per [DECISION] #1
// (resolved via D-104/G-70): the issued leaf carries the alt-public-key but
// NOT an alt-signature -- leaf-key protection is the accepted product
// scope, and a classical CA couldn't produce a real ML-DSA issuer signature
// regardless.
func TestIssueCertificateFromHybridCSR_AnyCAIssuesHybridLeaf(t *testing.T) {
	pair := newTestHybridKeyPair(t, keystore.HybridECDSAP256MLDSA65)
	der, err := CreateCertificateRequestHybrid(pkix.Name{CommonName: "hybrid-leaf.example.com"}, []string{"hybrid-leaf.example.com"}, nil, pair.Primary, pair.Secondary, keystore.HybridECDSAP256MLDSA65)
	if err != nil {
		t.Fatalf("CreateCertificateRequestHybrid: %v", err)
	}
	hybridCSR, err := ParseCertificateRequestHybrid(der)
	if err != nil {
		t.Fatalf("ParseCertificateRequestHybrid: %v", err)
	}

	for _, tc := range []struct {
		name string
		algo keystore.Algorithm
	}{
		{"classical CA", keystore.ECDSAP256},
		{"ML-DSA CA", keystore.MLDSA65},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var engine *Engine
			if tc.algo == keystore.MLDSA65 {
				engine = newMLDSATestEngine(t)
			} else {
				engine = newTestEngine(t)
			}
			root, err := engine.CreateRootCA("Hybrid Issuer Test CA", pkix.Name{CommonName: "Hybrid Issuer Test CA"}, tc.algo, 10*365*24*time.Hour)
			if err != nil {
				t.Fatalf("create root CA: %v", err)
			}

			issued, err := engine.IssueCertificate(root.ID, IssuanceRequest{HybridCSR: hybridCSR})
			if err != nil {
				t.Fatalf("IssueCertificate with HybridCSR: %v", err)
			}
			if issued.Certificate.Subject.CommonName != "hybrid-leaf.example.com" {
				t.Errorf("CommonName = %q, want hybrid-leaf.example.com", issued.Certificate.Subject.CommonName)
			}

			hasAltKey, hasAltSig, altPubBytes, _ := HybridCertInfo(issued.Certificate)
			if !hasAltKey {
				t.Error("expected hasAltKey=true, got false")
			}
			if hasAltSig {
				t.Error("expected hasAltSig=false (D-104: leaf-key protection only, no issuer alt-signature), got true")
			}
			// HybridCertInfo only inspects 2.5.29.72/.74, so pin the shape
			// directly: altSignatureAlgorithm (2.5.29.73) identifies the
			// algorithm of an altSignatureValue that must not exist here --
			// emitting it alone would describe a signature that isn't
			// present (see engine.go's issueCertificateFromHybridCSR).
			for _, ext := range issued.Certificate.Extensions {
				if ext.Id.Equal(oidAltSignatureAlgorithm) {
					t.Error("issued leaf must not carry altSignatureAlgorithm (2.5.29.73) without a corresponding altSignatureValue")
				}
			}
			wantAltBytes, err := pair.Secondary.Public().(keystore.MLDSAPublicKey).MarshalBinary()
			if err != nil {
				t.Fatalf("marshal want alt pub: %v", err)
			}
			if string(altPubBytes) != string(wantAltBytes) {
				t.Error("issued cert's alt public key does not match the CSR's alt public key")
			}
		})
	}
}
