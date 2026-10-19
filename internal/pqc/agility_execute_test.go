// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package pqc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"strings"
	"testing"

	"kryptkeeper/internal/keystore"
)

func newTransitionStore(t *testing.T) keystore.Store {
	t.Helper()
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("test-passphrase-not-for-production"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	return keys
}

func TestBuildTransitionCSR_ECDSAP384(t *testing.T) {
	keys := newTransitionStore(t)
	m, err := BuildTransitionCSR(keys, "k1", keystore.ECDSAP384, pkix.Name{CommonName: "svc.example.com"}, []string{"svc.example.com"}, nil)
	if err != nil {
		t.Fatalf("BuildTransitionCSR: %v", err)
	}
	block, _ := pem.Decode([]byte(m.CSRPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("PEM block = %+v, want CERTIFICATE REQUEST", block)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("signature: %v", err)
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P384() {
		t.Fatalf("public key = %T, want P-384 ECDSA", csr.PublicKey)
	}
	if csr.Subject.CommonName != "svc.example.com" || len(csr.DNSNames) != 1 || csr.DNSNames[0] != "svc.example.com" {
		t.Errorf("CN/SANs not carried: %q %v", csr.Subject.CommonName, csr.DNSNames)
	}
}

func TestBuildTransitionCSR_PQCDelegates(t *testing.T) {
	m, err := BuildTransitionCSR(newTransitionStore(t), "k2", keystore.MLDSA65, pkix.Name{CommonName: "pq.example.com"}, []string{"pq.example.com"}, nil)
	if err != nil {
		t.Fatalf("BuildTransitionCSR: %v", err)
	}
	block, _ := pem.Decode([]byte(m.CSRPEM))
	if block == nil || block.Type != "ML-DSA CERTIFICATE REQUEST" {
		t.Fatalf("PEM block = %+v, want ML-DSA CERTIFICATE REQUEST", block)
	}
}

func TestBuildTransitionCSR_RejectsUnknown(t *testing.T) {
	_, err := BuildTransitionCSR(newTransitionStore(t), "k3", keystore.Algorithm("DES-3"), pkix.Name{CommonName: "x"}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "DES-3") {
		t.Fatalf("err = %v, want one naming DES-3", err)
	}
}

func TestIsTransitionTarget(t *testing.T) {
	cases := map[keystore.Algorithm]bool{
		keystore.RSA3072: true, keystore.RSA4096: true, keystore.ECDSAP256: true,
		keystore.ECDSAP384: true, keystore.Ed25519: true, keystore.MLDSA65: true,
		keystore.HybridECDSAP256MLDSA65: true,
		keystore.RSA2048:                false, "DES-3": false,
	}
	for a, want := range cases {
		if got := IsTransitionTarget(a); got != want {
			t.Errorf("IsTransitionTarget(%s) = %v, want %v", a, got, want)
		}
	}
}
