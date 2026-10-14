// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"kryptkeeper/internal/keystore"
)

func fakeSPKI(t *testing.T, oid asn1.ObjectIdentifier) []byte {
	t.Helper()
	der, err := asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: oid},
		PublicKey: asn1.BitString{Bytes: []byte{1, 2, 3}, BitLength: 24},
	})
	if err != nil {
		t.Fatalf("marshal spki: %v", err)
	}
	return der
}

func TestStoredPublicKeyAlgorithm(t *testing.T) {
	for _, oid := range []asn1.ObjectIdentifier{keystore.OIDMLDsa44, keystore.OIDMLDsa65, keystore.OIDMLDsa87} {
		cert := &x509.Certificate{RawSubjectPublicKeyInfo: fakeSPKI(t, oid)}
		if got := StoredPublicKeyAlgorithm(cert); got != "ML-DSA" {
			t.Errorf("oid %v: got %q, want ML-DSA", oid, got)
		}
	}

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		pub    any
		signer any
		want   string
	}{{&ecKey.PublicKey, ecKey, "ECDSA"}, {edPub, edPriv, "Ed25519"}} {
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "x"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, tc.pub, tc.signer)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		if got := StoredPublicKeyAlgorithm(cert); got != tc.want {
			t.Errorf("got %q, want %q", got, tc.want)
		}
	}
}
