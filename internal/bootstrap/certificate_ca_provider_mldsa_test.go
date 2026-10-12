// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

func newTestMLDSACAProvider(t *testing.T) (CertificateProvider, *ca.Engine, keystore.Store) {
	t.Helper()
	dir := t.TempDir()
	keys, err := keystore.NewSoftwareStore(dir, []byte("test-passphrase-for-ca-provider!"))
	if err != nil {
		t.Fatalf("create keystore: %v", err)
	}
	engine := ca.NewEngine(keys, ca.NewMemStore())

	_, err = engine.CreateRootCA("ML-DSA Test Root", pkix.Name{
		CommonName: "ML-DSA Test Root CA",
	}, keystore.MLDSA65, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("create ML-DSA root CA: %v", err)
	}

	return NewCACertificateProvider(engine, ca.NewMemRevocationStore(), nil, false), engine, keys
}

func generateTestMLDSACSRPEM(t *testing.T, keys keystore.Store, cn string, sans ...string) (string, keystore.MLDSAPublicKey) {
	t.Helper()
	keyID := "leaf-mldsa-" + cn
	if _, err := keys.GenerateKey(keyID, keystore.MLDSA65); err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	signer, err := keys.Signer(keyID)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	der, err := ca.CreateCertificateRequestMLDSA(pkix.Name{CommonName: cn}, sans, nil, signer, keystore.MLDSA65)
	if err != nil {
		t.Fatalf("CreateCertificateRequestMLDSA: %v", err)
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "ML-DSA CERTIFICATE REQUEST", Bytes: der}))
	return csrPEM, signer.Public().(keystore.MLDSAPublicKey)
}

func TestCACertificateProviderIssueAndQuery_MLDSALeaf(t *testing.T) {
	provider, engine, keys := newTestMLDSACAProvider(t)
	caID := getFirstCAID(t, engine)
	ctx := context.Background()

	csrPEM, leafPub := generateTestMLDSACSRPEM(t, keys, "mldsa-leaf.example.com", "mldsa-leaf.example.com", "www.mldsa-leaf.example.com")

	result, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       caID,
		TemplateID: "tpl-tls",
		CSRPEM:     csrPEM,
		TeamID:     "team-1",
	})
	if err != nil {
		t.Fatalf("issue ML-DSA leaf: %v", err)
	}
	if result.FingerprintSHA256 == "" {
		t.Fatal("expected non-empty fingerprint")
	}
	if result.CommonName != "mldsa-leaf.example.com" {
		t.Errorf("CommonName = %q, want mldsa-leaf.example.com", result.CommonName)
	}
	// G-67 closeout gap advisor caught: confirm SANs actually survive
	// issuance -- certificate_ca_provider.go never populates
	// IssuanceRequest.DNSNames for either CSR type, so without the CSR's own
	// SAN attribute (encodeSANAttribute/decodeSANAttribute) + the
	// issueCertificateFromPQCCSR fallback, every ML-DSA cert would silently
	// carry zero SANs.
	wantSANs := []string{"mldsa-leaf.example.com", "www.mldsa-leaf.example.com"}
	if len(result.SubjectAltNames) != len(wantSANs) {
		t.Fatalf("SubjectAltNames = %v, want %v", result.SubjectAltNames, wantSANs)
	}
	for i, want := range wantSANs {
		if result.SubjectAltNames[i] != want {
			t.Errorf("SubjectAltNames[%d] = %q, want %q", i, result.SubjectAltNames[i], want)
		}
	}

	// Verify the ACTUAL issued certificate (not just re-deriving the same
	// keystore signer, which would trivially match itself) embeds the CSR's
	// public key. Download the real DER, re-parse it independently, and
	// confirm the raw SubjectPublicKeyInfo carries the CSR's ML-DSA public
	// key bytes.
	download, err := provider.DownloadCertificate(ctx, result.FingerprintSHA256, "der", false)
	if err != nil {
		t.Fatalf("download issued cert: %v", err)
	}
	reparsed, err := x509.ParseCertificate(download.Body)
	if err != nil {
		t.Fatalf("re-parse issued cert DER: %v", err)
	}
	wantPubBytes, err := leafPub.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal want pub: %v", err)
	}
	if !bytes.Contains(reparsed.RawSubjectPublicKeyInfo, wantPubBytes) {
		t.Fatal("issued certificate's RawSubjectPublicKeyInfo does not contain the CSR's ML-DSA public key bytes")
	}
}

// TestCACertificateProviderRenewFlow_MLDSALeaf mirrors
// TestCACertificateProviderRenewFlow (certificate_ca_provider_test.go) for
// the ML-DSA path -- RenewCertificate is named in W4-07's acceptance
// criterion 3 and was modified by this ticket (PEM block-type dispatch), so
// it needs its own coverage, not just IssueCertificate's. Also proves the
// SAN-preservation fallback (see issueCertificateFromPQCCSR) applies on
// renewal too, not only fresh issuance.
func TestCACertificateProviderRenewFlow_MLDSALeaf(t *testing.T) {
	provider, engine, keys := newTestMLDSACAProvider(t)
	caID := getFirstCAID(t, engine)
	ctx := context.Background()

	csrPEM, _ := generateTestMLDSACSRPEM(t, keys, "renew-mldsa.example.com", "renew-mldsa.example.com")
	original, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       caID,
		TemplateID: "tpl-tls",
		CSRPEM:     csrPEM,
		TeamID:     "team-1",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	renewCSR, _ := generateTestMLDSACSRPEM(t, keys, "renew-mldsa.example.com-2", "renew-mldsa.example.com")
	renewed, err := provider.RenewCertificate(ctx, original.FingerprintSHA256, CertificateRenewRequest{CSRPEM: renewCSR})
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if renewed.FingerprintSHA256 == original.FingerprintSHA256 {
		t.Error("renewed cert should have different fingerprint")
	}
	if renewed.PredecessorFP == nil || *renewed.PredecessorFP != original.FingerprintSHA256 {
		t.Error("renewed cert should link to predecessor")
	}
	if len(renewed.SubjectAltNames) != 1 || renewed.SubjectAltNames[0] != "renew-mldsa.example.com" {
		t.Errorf("SubjectAltNames = %v, want [renew-mldsa.example.com] -- renewal must not silently drop SANs", renewed.SubjectAltNames)
	}
}

func TestCACertificateProviderIssueCertificate_UnrecognizedPEMBlockType(t *testing.T) {
	provider, _, _ := newTestMLDSACAProvider(t)
	ctx := context.Background()

	badPEM := string(pem.EncodeToMemory(&pem.Block{Type: "SOMETHING ELSE", Bytes: []byte("not a real csr")}))
	_, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       "does-not-matter",
		TemplateID: "tpl-tls",
		CSRPEM:     badPEM,
		TeamID:     "team-1",
	})
	if err == nil {
		t.Fatal("expected an error for an unrecognized PEM block type")
	}
}
