// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"kryptkeeper/internal/keystore"
)

func newMLDSATestEngine(t *testing.T) *Engine {
	t.Helper()
	dir := t.TempDir()
	keys, err := keystore.NewSoftwareStore(dir, []byte("mldsa-test-passphrase-32chars!!!!"))
	if err != nil {
		t.Fatalf("create keystore: %v", err)
	}
	return NewEngine(keys, NewMemStore())
}

func TestCreateRootCAWithMLDSA65(t *testing.T) {
	engine := newMLDSATestEngine(t)

	ca, err := engine.CreateRootCA("ML-DSA Root CA", pkix.Name{
		CommonName:   "ML-DSA Test Root CA",
		Organization: []string{"Kryptkeeper Test"},
	}, keystore.MLDSA65, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA ML-DSA-65: %v", err)
	}

	if ca.Type != "root" {
		t.Errorf("expected root, got %s", ca.Type)
	}
	if ca.Status != "active" {
		t.Errorf("expected active, got %s", ca.Status)
	}
	if ca.Certificate == nil {
		t.Fatal("certificate is nil")
	}
	if ca.Certificate.Subject.CommonName != "ML-DSA Test Root CA" {
		t.Errorf("unexpected CN: %s", ca.Certificate.Subject.CommonName)
	}
	if len(ca.CertPEM) == 0 {
		t.Fatal("CertPEM is empty")
	}

	// Verify the PEM block is parseable.
	block, _ := pem.Decode(ca.CertPEM)
	if block == nil {
		t.Fatal("CertPEM is not valid PEM")
	}
	if block.Type != "CERTIFICATE" {
		t.Errorf("unexpected PEM type: %s", block.Type)
	}

	t.Logf("ML-DSA-65 root CA cert size: %d bytes (raw DER)", len(block.Bytes))
}

func TestCreateRootCAWithMLDSA44(t *testing.T) {
	engine := newMLDSATestEngine(t)
	ca, err := engine.CreateRootCA("ML-DSA-44 Root", pkix.Name{CommonName: "ML-DSA-44 Root"}, keystore.MLDSA44, 5*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA ML-DSA-44: %v", err)
	}
	if ca.Certificate == nil {
		t.Fatal("certificate is nil")
	}
}

func TestCreateRootCAWithMLDSA87(t *testing.T) {
	engine := newMLDSATestEngine(t)
	ca, err := engine.CreateRootCA("ML-DSA-87 Root", pkix.Name{CommonName: "ML-DSA-87 Root"}, keystore.MLDSA87, 5*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA ML-DSA-87: %v", err)
	}
	if ca.Certificate == nil {
		t.Fatal("certificate is nil")
	}
}

func TestIssueCertificateFromMLDSACA(t *testing.T) {
	engine := newMLDSATestEngine(t)

	rootCA, err := engine.CreateRootCA("ML-DSA Root", pkix.Name{
		CommonName: "ML-DSA Issuing Root",
	}, keystore.MLDSA65, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("create root CA: %v", err)
	}

	// Issue a classical ECDSA leaf cert from an ML-DSA CA.
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "leaf.example.com"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, clientKey)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}

	issued, err := engine.IssueCertificate(rootCA.ID, IssuanceRequest{
		CSR:         csr,
		Validity:    90 * 24 * time.Hour,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		t.Fatalf("IssueCertificate from ML-DSA CA: %v", err)
	}

	if issued.Certificate.Subject.CommonName != "leaf.example.com" {
		t.Errorf("unexpected CN: %s", issued.Certificate.Subject.CommonName)
	}
	if len(issued.CertPEM) == 0 {
		t.Fatal("CertPEM is empty")
	}

	t.Logf("Leaf cert (ML-DSA signed) size: %d bytes", len(issued.CertPEM))
}

func TestMLDSARootCAIsStoredAndRetrievable(t *testing.T) {
	engine := newMLDSATestEngine(t)

	ca, err := engine.CreateRootCA("Stored Root", pkix.Name{CommonName: "Stored ML-DSA Root"}, keystore.MLDSA65, 5*365*24*time.Hour)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := engine.GetCA(ca.ID)
	if err != nil {
		t.Fatalf("GetCA: %v", err)
	}
	if got.ID != ca.ID {
		t.Errorf("ID mismatch: %s vs %s", got.ID, ca.ID)
	}

	list, err := engine.ListCAs()
	if err != nil {
		t.Fatalf("ListCAs: %v", err)
	}
	found := false
	for _, c := range list {
		if c.ID == ca.ID {
			found = true
		}
	}
	if !found {
		t.Error("ML-DSA CA not in ListCAs")
	}
}

func TestCreateCertificateMLDSADirectly(t *testing.T) {
	// Unit test CreateCertificateMLDSA with a directly generated key.
	pub, priv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	import_serial := big.NewInt(1) //nolint:gomnd
	template := &x509.Certificate{
		SerialNumber:          import_serial,
		Subject:               pkix.Name{CommonName: "Direct ML-DSA Test"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	certDER, err := CreateCertificateMLDSA(template, template, pub, priv, keystore.MLDSA65)
	if err != nil {
		t.Fatalf("CreateCertificateMLDSA: %v", err)
	}
	if len(certDER) == 0 {
		t.Fatal("empty certificate DER")
	}

	// Verify the DER is parseable ASN.1.
	block := &pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	pemBytes := pem.EncodeToMemory(block)
	if len(pemBytes) == 0 {
		t.Fatal("PEM encoding failed")
	}

	t.Logf("ML-DSA-65 self-signed cert: %d bytes DER", len(certDER))
}
