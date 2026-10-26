// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func selfSignedClientCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "hub"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestClientPresentsClientCertificateUnderPolicy(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "no client cert", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())

	withCert := NewClient(Policy{AllowLoopback: true, RootCAs: roots, ClientCertificates: []tls.Certificate{selfSignedClientCert(t)}})
	resp, err := withCert.Get(srv.URL)
	if err != nil {
		t.Fatalf("mTLS request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status %d", resp.StatusCode)
	}

	without := NewClient(Policy{AllowLoopback: true, RootCAs: roots})
	if resp, err := without.Get(srv.URL); err == nil {
		resp.Body.Close()
		t.Fatal("server requiring a client certificate must refuse a client without one")
	}

	// A client certificate never widens the address policy.
	guarded := NewClient(Policy{RootCAs: roots, ClientCertificates: []tls.Certificate{selfSignedClientCert(t)}})
	if resp, err := guarded.Get(srv.URL); err == nil {
		resp.Body.Close()
		t.Fatal("loopback must stay blocked when AllowLoopback is false")
	}
}
