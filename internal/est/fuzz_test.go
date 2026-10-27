// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package est

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
)

// FuzzParseCSRFromRequest feeds the RFC 7030 simpleenroll body parser (PEM,
// base64 DER or raw DER) the bytes a network client controls. A rejection is
// fine; a panic, or success with a nil request, is not.
func FuzzParseCSRFromRequest(f *testing.F) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "fuzz.example.com"},
		DNSNames: []string{"fuzz.example.com"},
	}, key)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(der)
	f.Add([]byte(base64.StdEncoding.EncodeToString(der)))
	f.Add(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	f.Add([]byte("-----BEGIN CERTIFICATE REQUEST-----\n!!!\n-----END CERTIFICATE REQUEST-----\n"))
	f.Add([]byte{})

	s := &Server{}
	f.Fuzz(func(t *testing.T, body []byte) {
		r := httptest.NewRequest(http.MethodPost, "/.well-known/est/simpleenroll", bytes.NewReader(body))
		csr, err := s.parseCSRFromRequest(r)
		if err == nil && csr == nil {
			t.Fatal("nil CSR with nil error")
		}
	})
}
