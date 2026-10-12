// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

func TestCACertificateProviderIssueAndQuery_HybridLeaf(t *testing.T) {
	dir := t.TempDir()
	keys, err := keystore.NewSoftwareStore(dir, []byte("test-passphrase-for-ca-provider!"))
	if err != nil {
		t.Fatalf("create keystore: %v", err)
	}
	engine := ca.NewEngine(keys, ca.NewMemStore())
	// Realistic W4-03 case: a classical (not ML-DSA) issuing CA.
	if _, err := engine.CreateRootCA("Hybrid E2E Test Root", pkix.Name{
		CommonName: "Hybrid E2E Test Root CA",
	}, keystore.ECDSAP256, 10*365*24*time.Hour); err != nil {
		t.Fatalf("create root CA: %v", err)
	}
	provider := NewCACertificateProvider(engine, ca.NewMemRevocationStore(), nil, false)
	caID := getFirstCAID(t, engine)
	ctx := context.Background()

	if _, err := keys.GenerateKey("hybrid-e2e-leaf", keystore.HybridECDSAP256MLDSA65); err != nil {
		t.Fatalf("generate hybrid leaf key: %v", err)
	}
	pair, err := keys.LoadHybridKeyPair("hybrid-e2e-leaf")
	if err != nil {
		t.Fatalf("load hybrid key pair: %v", err)
	}
	der, err := ca.CreateCertificateRequestHybrid(pkix.Name{CommonName: "hybrid-e2e.example.com"}, []string{"hybrid-e2e.example.com", "www.hybrid-e2e.example.com"}, nil, pair.Primary, pair.Secondary, keystore.HybridECDSAP256MLDSA65)
	if err != nil {
		t.Fatalf("CreateCertificateRequestHybrid: %v", err)
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "HYBRID CERTIFICATE REQUEST", Bytes: der}))

	result, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       caID,
		TemplateID: "tpl-tls",
		CSRPEM:     csrPEM,
		TeamID:     "team-1",
	})
	if err != nil {
		t.Fatalf("issue hybrid leaf: %v", err)
	}
	if result.CommonName != "hybrid-e2e.example.com" {
		t.Errorf("CommonName = %q, want hybrid-e2e.example.com", result.CommonName)
	}

	wantSANs := []string{"hybrid-e2e.example.com", "www.hybrid-e2e.example.com"}
	if len(result.SubjectAltNames) != len(wantSANs) {
		t.Fatalf("SubjectAltNames = %v, want %v", result.SubjectAltNames, wantSANs)
	}
	for i, want := range wantSANs {
		if result.SubjectAltNames[i] != want {
			t.Errorf("SubjectAltNames[%d] = %q, want %q", i, result.SubjectAltNames[i], want)
		}
	}

	// Confirm the alt-key survived the full round trip through the real
	// issuance path by re-parsing the actual issued DER independently.
	download, err := provider.DownloadCertificate(ctx, result.FingerprintSHA256, "der", false)
	if err != nil {
		t.Fatalf("download issued cert: %v", err)
	}
	reparsed, err := x509.ParseCertificate(download.Body)
	if err != nil {
		t.Fatalf("re-parse issued cert: %v", err)
	}
	hasAltKey, hasAltSig, altPubBytes, _ := ca.HybridCertInfo(reparsed)
	if !hasAltKey {
		t.Error("expected the issued cert to carry an alt public key")
	}
	if hasAltSig {
		t.Error("expected no alt signature on a leaf-key-protection-only hybrid cert (D-104)")
	}
	// Pin the extension shape directly (HybridCertInfo only checks
	// 2.5.29.72/.74): altSignatureAlgorithm (2.5.29.73) without a
	// corresponding altSignatureValue would misdescribe a signature that
	// doesn't exist.
	for _, ext := range reparsed.Extensions {
		if ext.Id.String() == "2.5.29.73" {
			t.Error("issued leaf must not carry altSignatureAlgorithm (2.5.29.73) without a corresponding altSignatureValue")
		}
	}
	wantAltBytes, err := pair.Secondary.Public().(keystore.MLDSAPublicKey).MarshalBinary()
	if err != nil {
		t.Fatalf("marshal want alt pub: %v", err)
	}
	if string(altPubBytes) != string(wantAltBytes) {
		t.Error("issued cert's alt public key does not match the CSR's")
	}
}
