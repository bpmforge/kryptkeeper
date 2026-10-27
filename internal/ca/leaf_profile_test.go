// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
	"time"

	"kryptkeeper/internal/keystore"
)

const defaultLeafKU = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment

func TestLeafKeyUsage(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	server := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	tests := []struct {
		name string
		pub  any
		ekus []x509.ExtKeyUsage
		want x509.KeyUsage
	}{
		{"ecdsa drops keyEncipherment", &ec.PublicKey, server, x509.KeyUsageDigitalSignature},
		{"rsa server keeps keyEncipherment", &rk.PublicKey, server, defaultLeafKU},
		{"rsa client keeps keyEncipherment", &rk.PublicKey, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, defaultLeafKU},
		{"rsa code signing drops keyEncipherment", &rk.PublicKey, []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, x509.KeyUsageDigitalSignature},
		{"rsa ocsp signing drops keyEncipherment", &rk.PublicKey, []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}, x509.KeyUsageDigitalSignature},
		{"rsa time stamping drops keyEncipherment", &rk.PublicKey, []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}, x509.KeyUsageDigitalSignature},
		{"ml-dsa drops keyEncipherment", struct{}{}, server, x509.KeyUsageDigitalSignature},
		{"enciphering-only EC key still gets a usage", &ec.PublicKey, server, x509.KeyUsageDigitalSignature},
	}
	for _, tc := range tests {
		in := defaultLeafKU
		if tc.name == "enciphering-only EC key still gets a usage" {
			in = x509.KeyUsageKeyEncipherment
		}
		if got := leafKeyUsage(in, tc.ekus, tc.pub); got != tc.want {
			t.Errorf("%s: got %b, want %b", tc.name, got, tc.want)
		}
	}
	if got := leafKeyUsage(0, server, &ec.PublicKey); got != 0 {
		t.Errorf("zero usage must stay zero, got %b", got)
	}
}

func issueLeafWithEKU(t *testing.T, ekus ...x509.ExtKeyUsage) *x509.Certificate {
	t.Helper()
	engine := newTestEngine(t)
	root, err := engine.CreateRootCA("Root", pkix.Name{CommonName: "Root"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "leaf"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := engine.IssueCertificate(root.ID, IssuanceRequest{
		CSR: csr, Validity: 24 * time.Hour, KeyUsage: defaultLeafKU, ExtKeyUsage: ekus,
	})
	if err != nil {
		t.Fatal(err)
	}
	return issued.Certificate
}

func findExt(c *x509.Certificate, id asn1.ObjectIdentifier) (pkix.Extension, bool) {
	for _, e := range c.Extensions {
		if e.Id.Equal(id) {
			return e, true
		}
	}
	return pkix.Extension{}, false
}

func TestIssuedTimeStampingEKUIsCritical(t *testing.T) {
	cert := issueLeafWithEKU(t, x509.ExtKeyUsageTimeStamping)
	ext, ok := findExt(cert, oidExtKeyUsage)
	if !ok || !ext.Critical {
		t.Fatalf("EKU present=%v critical=%v, want a critical extension (RFC 3161 2.3)", ok, ext.Critical)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageTimeStamping {
		t.Errorf("parsed EKU = %v, want [timeStamping]", cert.ExtKeyUsage)
	}
	n := 0
	for _, e := range cert.Extensions {
		if e.Id.Equal(oidExtKeyUsage) {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d EKU extensions, want exactly 1", n)
	}
	if cert.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("key usage = %b, want digitalSignature only", cert.KeyUsage)
	}
}

func TestIssuedOCSPSigningCarriesNoCheck(t *testing.T) {
	cert := issueLeafWithEKU(t, x509.ExtKeyUsageOCSPSigning)
	if _, ok := findExt(cert, oidOCSPNoCheck); !ok {
		t.Error("OCSP responder certificate lacks id-pkix-ocsp-nocheck (RFC 6960 4.2.2.2.1)")
	}
	if ext, _ := findExt(issueLeafWithEKU(t, x509.ExtKeyUsageServerAuth), oidExtKeyUsage); ext.Critical {
		t.Error("serverAuth EKU must stay non-critical")
	}
	if _, ok := findExt(issueLeafWithEKU(t, x509.ExtKeyUsageServerAuth), oidOCSPNoCheck); ok {
		t.Error("nocheck must only appear on OCSP signing certificates")
	}
}
