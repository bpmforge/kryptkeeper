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
	"os"
	"testing"
)

func TestCSRPublicKeyAlgorithmOID_ClassicalIsNotMLDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "c"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	oid, err := CSRPublicKeyAlgorithmOID(der)
	if err != nil {
		t.Fatalf("CSRPublicKeyAlgorithmOID: %v", err)
	}
	if oid.String() != "1.2.840.10045.2.1" {
		t.Errorf("oid = %s, want id-ecPublicKey", oid)
	}
	if IsMLDSACSR(der) {
		t.Error("ECDSA CSR must not be routed to the ML-DSA parser")
	}
}

func TestIsMLDSACSR_MalformedDERIsFalse(t *testing.T) {
	if IsMLDSACSR([]byte("not der")) {
		t.Error("malformed DER must not report ML-DSA")
	}
	if IsMLDSACSR(nil) {
		t.Error("empty input must not report ML-DSA")
	}
}

// The fixture is a real openssl 3.6 PKCS#10 request (public data only; the
// throwaway key was discarded) emitted under the standard PEM label, the
// shape the label-only router used to send to crypto/x509.
func TestOpenSSLMLDSA65StandardLabelCSR(t *testing.T) {
	raw, err := os.ReadFile("testdata/openssl_mldsa65_std_label.csr")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("fixture must carry the standard label, got %+v", block)
	}
	if !IsMLDSACSR(block.Bytes) {
		t.Fatal("openssl ML-DSA-65 CSR not recognised by OID")
	}
	parsed, err := ParseCertificateRequestMLDSA(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificateRequestMLDSA (verifies self-signature): %v", err)
	}
	if parsed.Subject.CommonName != "pq.example.test" {
		t.Errorf("CN = %q", parsed.Subject.CommonName)
	}
}
