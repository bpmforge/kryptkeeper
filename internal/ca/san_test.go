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
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"
)

func TestSubjectAltNameStringsCollectsEveryKind(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	spiffeURI, err := url.Parse("spiffe://kk.local/ns/default/sa/iis-lab")
	if err != nil {
		t.Fatalf("parse spiffe uri: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(1),
		Subject:        pkix.Name{CommonName: "iis-lab.kk.local"},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(24 * time.Hour),
		DNSNames:       []string{"iis-lab.kk.local"},
		IPAddresses:    []net.IP{net.ParseIP("192.0.2.10")},
		URIs:           []*url.URL{spiffeURI},
		EmailAddresses: []string{"ops@kk.local"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	got := SubjectAltNameStrings(cert)
	want := []string{"iis-lab.kk.local", "192.0.2.10", "spiffe://kk.local/ns/default/sa/iis-lab", "ops@kk.local"}
	if len(got) != len(want) {
		t.Fatalf("SubjectAltNameStrings = %v, want %v", got, want)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("SubjectAltNameStrings[%d] = %q, want %q (full: %v)", i, got[i], w, got)
		}
	}
}

func TestSubjectAltNameStringsNeverNil(t *testing.T) {
	cert := &x509.Certificate{}
	if got := SubjectAltNameStrings(cert); got == nil {
		t.Fatal("SubjectAltNameStrings returned nil, want empty slice")
	}
}
