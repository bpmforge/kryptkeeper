// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// W14-04: crypto-posture probe — negotiated/offered versions, weak
// findings, and ML-KEM-on-the-wire detection against fixture listeners.

func postureServerCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "posture.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(60 * 24 * time.Hour),
		DNSNames:     []string{"posture.example.com"},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// tlsListener serves TLS with the given config for the test's duration.
func tlsListener(t *testing.T, cfg *tls.Config) (string, int) {
	t.Helper()
	cfg.Certificates = []tls.Certificate{postureServerCert(t)}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
				_ = c.Close()
			}(conn)
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port
}

func TestPostureNegotiatedAndOfferedVersions(t *testing.T) {
	// Server pinned to TLS 1.2 only.
	host, port := tlsListener(t, &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12})
	cp := NewPostureProber(3*time.Second).ProbeEndpoint(context.Background(), host, port)
	if cp.Error != "" {
		t.Fatalf("probe error: %s", cp.Error)
	}
	if cp.NegotiatedVersion != "TLSv1.2" {
		t.Fatalf("negotiated version: %q", cp.NegotiatedVersion)
	}
	if !containsStr(cp.OfferedVersions, "TLSv1.2") {
		t.Fatalf("TLS 1.2 must be offered: %v", cp.OfferedVersions)
	}
	if containsStr(cp.OfferedVersions, "TLSv1.3") {
		t.Fatalf("TLS 1.3 must not be offered by a 1.2-pinned server: %v", cp.OfferedVersions)
	}
	if cp.NegotiatedCipher == "" {
		t.Fatal("negotiated cipher must be captured")
	}
}

func TestPostureDetectsMLKEMOnTheWire(t *testing.T) {
	// TLS 1.3 server that allows the ML-KEM hybrid group.
	host, port := tlsListener(t, &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
	})
	cp := NewPostureProber(3*time.Second).ProbeEndpoint(context.Background(), host, port)
	if cp.Error != "" {
		t.Fatalf("probe error: %s", cp.Error)
	}
	if !cp.PQC.HybridNegotiated {
		t.Fatalf("ML-KEM must be detected as negotiated: group=%q", cp.PQC.Group)
	}
	if !strings.Contains(strings.ToUpper(cp.PQC.Group), "MLKEM") {
		t.Fatalf("negotiated group must name ML-KEM: %q", cp.PQC.Group)
	}
	if !cp.PQC.HybridOffered {
		t.Fatal("ML-KEM must be reported offered")
	}
}

func TestPostureWeakVersionFinding(t *testing.T) {
	// Server allowing TLS 1.0 (deprecated).
	host, port := tlsListener(t, &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS12})
	cp := NewPostureProber(3*time.Second).ProbeEndpoint(context.Background(), host, port)
	found := false
	for _, f := range cp.WeakFindings {
		if strings.Contains(f, "TLSv1.0") {
			found = true
		}
	}
	if !found {
		t.Fatalf("TLS 1.0 offering must be a weak finding: %v", cp.WeakFindings)
	}
}

func TestPostureUnreachableErrors(t *testing.T) {
	cp := NewPostureProber(time.Second).ProbeEndpoint(context.Background(), "127.0.0.1", 1)
	if cp.Error == "" {
		t.Fatal("unreachable endpoint must report an error")
	}
}

func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
