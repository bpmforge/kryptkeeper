// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // SHA-1 CertIDs
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/ocsp"
)

// W36-02: the hub publishes no CRL or OCSP for an external CA.

func newExternalCAForTest(t *testing.T) (*ca.Engine, *ca.CA, *ca.CA) {
	t.Helper()
	engine, root := newOCSPResolveEngine(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "Upstream Root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ext, err := engine.CreateExternalCA("Upstream", "conn-1", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	return engine, root, ext
}

func TestExternalCAGuardAnswers404ForExternalCRL(t *testing.T) {
	engine, root, ext := newExternalCAForTest(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	h := externalCAGuard(engine, next)

	for _, path := range []string{"/crl/" + ext.ID + ".crl", "/crl/" + ext.ID + "/delta.crl"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), `"external_ca"`) {
			t.Errorf("%s: %d %s, want 404 external_ca", path, w.Code, w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/crl/"+root.ID+".crl", nil))
	if w.Code != http.StatusTeapot {
		t.Errorf("hub CA CRL must reach the generator, got %d", w.Code)
	}
}

func TestOCSPResolveIssuerByKeyHashExternalCA(t *testing.T) {
	engine, _, ext := newExternalCAForTest(t)
	h := ocspPublicKeyHash(ext.Certificate, sha1.Size)
	if _, err := ocspResolveIssuerByKeyHash(engine, h); !errors.Is(err, ocsp.ErrExternalIssuer) {
		t.Fatalf("err = %v, want ocsp.ErrExternalIssuer", err)
	}
}
