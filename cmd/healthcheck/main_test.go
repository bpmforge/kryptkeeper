// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRun_PlainHTTPHealthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if code := run(srv.URL+"/healthz", "", os.Stderr); code != 0 {
		t.Fatalf("run() = %d, want 0", code)
	}
}

func TestRun_PlainHTTPUnhealthyStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	if code := run(srv.URL+"/healthz", "", os.Stderr); code == 0 {
		t.Fatal("run() = 0, want nonzero for a 503 response")
	}
}

// TestRun_TLSWithTrustedCA is the positive TLS case W19-23 exists for: the
// hub's self-issued listener cert, verified against its own CA bundle.
func TestRun_TLSWithTrustedCA(t *testing.T) {
	srv, caPath := newTLSTestServer(t)
	defer srv.Close()

	if code := run(srv.URL+"/healthz", caPath, os.Stderr); code != 0 {
		t.Fatalf("run() = %d, want 0 with the matching CA file", code)
	}
}

// TestRun_TLSWithWrongCAFails is the negative case the ticket calls out
// explicitly: a healthcheck pointed at the wrong CA must fail closed, never
// fall back to accepting the connection anyway. Each newTLSTestServer call
// mints its own independent self-signed cert, so srv and other are
// certifiably not interchangeable.
func TestRun_TLSWithWrongCAFails(t *testing.T) {
	srv, _ := newTLSTestServer(t)
	defer srv.Close()

	other, wrongCAPath := newTLSTestServer(t)
	defer other.Close()

	if code := run(srv.URL+"/healthz", wrongCAPath, os.Stderr); code == 0 {
		t.Fatal("run() = 0, want nonzero when the CA file does not match the server's certificate")
	}
}

func TestRun_MissingCAFileFails(t *testing.T) {
	srv, _ := newTLSTestServer(t)
	defer srv.Close()

	if code := run(srv.URL+"/healthz", filepath.Join(t.TempDir(), "does-not-exist.pem"), os.Stderr); code == 0 {
		t.Fatal("run() = 0, want nonzero when HEALTHCHECK_CA_FILE does not exist")
	}
}

func TestNewHealthcheckClient_EmptyCAFileUsesSystemRoots(t *testing.T) {
	client, err := newHealthcheckClient("")
	if err != nil {
		t.Fatalf("newHealthcheckClient(\"\"): %v", err)
	}
	if client.Transport != nil {
		t.Error("expected the default transport (system roots) when no CA file is configured")
	}
}

func TestNewHealthcheckClient_EmptyPEMFileErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(path, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	if _, err := newHealthcheckClient(path); err == nil {
		t.Fatal("expected an error for a CA file with no PEM certificates")
	}
}

// newTLSTestServer starts an httptest server on a fresh, independently
// generated self-signed cert (unlike httptest.NewTLSServer, which reuses
// one fixed built-in test certificate/key across every call -- unsuitable
// for a wrong-CA negative test, since "wrong" and "right" would be
// byte-identical). Returns the server and the path to its cert's PEM.
func newTLSTestServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}},
	}
	srv.StartTLS()

	return srv, writeCertPEM(t, leaf)
}

func writeCertPEM(t *testing.T, cert *x509.Certificate) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o644); err != nil {
		t.Fatalf("writing CA fixture: %v", err)
	}
	return path
}
