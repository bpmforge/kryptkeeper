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
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestTLSServer(t *testing.T) *httptest.Server {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-scanner.example.com"},
		DNSNames:     []string{"test-scanner.example.com", "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certDER},
			PrivateKey:  key,
			Leaf:        cert,
		}},
	}
	ts.StartTLS()
	return ts
}

func TestScanLocalTLSServer(t *testing.T) {
	ts := newTestTLSServer(t)
	defer ts.Close()

	// Extract host:port from test server URL.
	target := ts.Listener.Addr().String()

	ep, err := ScanHost(context.Background(), target, 5*time.Second)
	if err != nil {
		t.Fatalf("scan host: %v", err)
	}

	if ep.Host == "" {
		t.Error("expected non-empty host")
	}
	if ep.Error != "" {
		t.Errorf("unexpected error: %s", ep.Error)
	}
	if len(ep.Certs) == 0 {
		t.Fatal("expected at least 1 certificate")
	}
	if ep.TLSVersion == "" {
		t.Error("expected non-empty TLS version")
	}

	cert := ep.Certs[0]
	if cert.CommonName != "test-scanner.example.com" {
		t.Errorf("expected CN=test-scanner.example.com, got %s", cert.CommonName)
	}
	if cert.Fingerprint == "" {
		t.Error("expected non-empty fingerprint")
	}
	if cert.SerialNumber == "" {
		t.Error("expected non-empty serial")
	}
	if len(cert.RiskFlags) == 0 {
		t.Error("expected at least PQC_VULNERABLE flag")
	}
}

func TestScanMultipleTargets(t *testing.T) {
	ts := newTestTLSServer(t)
	defer ts.Close()

	target := ts.Listener.Addr().String()

	s := New(ScanConfig{
		Targets:     []string{target, target}, // scan same server twice
		Concurrency: 2,
		Timeout:     5 * time.Second,
	})

	result := s.Scan(context.Background(), "multi-scan")
	if result.Status != "completed" {
		t.Errorf("expected completed, got %s", result.Status)
	}
	if result.TotalScanned != 2 {
		t.Errorf("expected 2 scanned, got %d", result.TotalScanned)
	}
	if result.CertsFound < 2 {
		t.Errorf("expected at least 2 certs found, got %d", result.CertsFound)
	}
}

func TestScanUnreachableHost(t *testing.T) {
	s := New(ScanConfig{
		Targets:     []string{"192.0.2.1:443"}, // RFC 5737 TEST-NET, should be unreachable
		Concurrency: 1,
		Timeout:     1 * time.Second,
	})

	result := s.Scan(context.Background(), "unreachable-scan")
	if result.TotalScanned != 1 {
		t.Errorf("expected 1 scanned, got %d", result.TotalScanned)
	}
	if result.ErrorCount != 1 {
		t.Errorf("expected 1 error, got %d", result.ErrorCount)
	}
	if len(result.Endpoints) != 1 || result.Endpoints[0].Error == "" {
		t.Error("expected error in endpoint")
	}
}

func TestScanCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	s := New(ScanConfig{
		Targets:     []string{"192.0.2.1:443"},
		Concurrency: 1,
		Timeout:     5 * time.Second,
	})

	result := s.Scan(ctx, "cancelled-scan")
	if result.Status != "failed" {
		t.Errorf("expected failed on cancellation, got %s", result.Status)
	}
}

func TestExpandCIDR(t *testing.T) {
	s := New(ScanConfig{
		Targets: []string{"10.0.0.0/30"},
		Ports:   []int{443},
	})
	targets := s.expandTargets()
	// /30 = 4 IPs (10.0.0.0, .1, .2, .3)
	if len(targets) != 4 {
		t.Errorf("expected 4 targets from /30 CIDR, got %d: %v", len(targets), targets)
	}
}

func TestRiskScoring(t *testing.T) {
	// Expired cert.
	expiredCert := &x509.Certificate{
		NotBefore:          time.Now().Add(-365 * 24 * time.Hour),
		NotAfter:           time.Now().Add(-1 * time.Hour),
		PublicKeyAlgorithm: x509.ECDSA,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	score, flags := computeCertRisk(expiredCert, "", true)
	if score < 40 {
		t.Errorf("expired cert should have score >= 40, got %d", score)
	}
	hasExpired := false
	for _, f := range flags {
		if f == "EXPIRED" {
			hasExpired = true
		}
	}
	if !hasExpired {
		t.Error("expected EXPIRED flag")
	}

	// SHA1 signed cert.
	sha1Cert := &x509.Certificate{
		NotBefore:          time.Now().Add(-1 * time.Hour),
		NotAfter:           time.Now().Add(365 * 24 * time.Hour),
		PublicKeyAlgorithm: x509.RSA,
		SignatureAlgorithm: x509.SHA1WithRSA,
	}
	score2, flags2 := computeCertRisk(sha1Cert, "", true)
	if score2 < 30 {
		t.Errorf("SHA1 cert should have score >= 30, got %d", score2)
	}
	hasWeak := false
	for _, f := range flags2 {
		if f == "WEAK_SIGNATURE" {
			hasWeak = true
		}
	}
	if !hasWeak {
		t.Error("expected WEAK_SIGNATURE flag")
	}
}

func TestPortsForScanType(t *testing.T) {
	// fast now sweeps the standard port of every cert/key protocol,
	// SSH included (the user asked quick scans to cover keys too).
	fast := PortsForScanType("fast")
	if !intsContain(fast, 443) || !intsContain(fast, 22) {
		t.Errorf("fast must include HTTPS(443) and SSH(22), got %v", fast)
	}
	targeted := PortsForScanType("targeted")
	if len(targeted) <= len(fast) {
		t.Errorf("targeted should be a superset of fast, got %v", targeted)
	}
	full := PortsForScanType("full")
	if len(full) <= len(targeted) {
		t.Errorf("full should be the widest catalogue, got %v", full)
	}
	// Tiers nest: every fast port is in targeted, every targeted in full.
	for _, p := range fast {
		if !intsContain(targeted, p) {
			t.Errorf("fast port %d missing from targeted", p)
		}
	}
	for _, p := range targeted {
		if !intsContain(full, p) {
			t.Errorf("targeted port %d missing from full", p)
		}
	}
	// Deduplicated (fullScanPorts intentionally contains a duplicate 8443).
	seen := map[int]bool{}
	for _, p := range full {
		if seen[p] {
			t.Errorf("full ports not deduplicated: %v", full)
		}
		seen[p] = true
	}
	// Unknown type falls back to fast, never empty.
	if got := PortsForScanType("bogus"); len(got) == 0 {
		t.Error("unknown scan type must not yield zero ports")
	}
}

func hasFlag(flags []string, want string) bool {
	for _, f := range flags {
		if f == want {
			return true
		}
	}
	return false
}

func intsContain(xs []int, want int) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func TestClassifyServerHeaderAndRecommendation(t *testing.T) {
	cases := map[string]struct{ tech, mode string }{
		"HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\n\r\n":    {"iis", "iis"},
		"HTTP/1.1 200 OK\r\nServer: Apache/2.4.57 (Win64)\r\n\r\n": {"apache", "ssh"},
		"HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\n\r\n":          {"nginx", "ssh"},
		"HTTP/1.1 200 OK\r\nServer: haproxy\r\n\r\n":               {"haproxy", "ssh"},
		"HTTP/1.1 200 OK\r\nX-Powered-By: ASP.NET\r\n\r\n":         {"iis", "iis"},
		"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n":       {"", ""},
	}
	for resp, want := range cases {
		tech := classifyServerHeader(resp)
		if tech != want.tech {
			t.Errorf("classify %q = %q, want %q", resp, tech, want.tech)
		}
		if got := recommendInstallMode(tech, "https"); got != want.mode {
			t.Errorf("recommend for %q = %q, want %q", tech, got, want.mode)
		}
	}
	// Apache on Windows: the point of the whole feature — the estate must
	// NOT blindly recommend iis for a Windows host running Apache.
	if recommendInstallMode(classifyServerHeader("HTTP/1.1 200 OK\r\nServer: Apache/2.4 (Win64)\r\n\r\n"), "https") == "iis" {
		t.Error("Apache-on-Windows must not be recommended the IIS install mode")
	}
}

func TestDeepOpenPortsFindsListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("port parse: %v", err)
	}
	// Sweep a small window around the open port (a full 65535 sweep is slow
	// and unnecessary for the unit check).
	lo, hi := port-2, port+2
	if lo < 1 {
		lo = 1
	}
	open := deepOpenPorts(context.Background(), "127.0.0.1", lo, hi)
	found := false
	for _, p := range open {
		if p == port {
			found = true
		}
	}
	if !found {
		t.Fatalf("deep sweep missed the open listener on %d: got %v", port, open)
	}
}

func TestDeepPortRangeHonorsNarrowing(t *testing.T) {
	lo, hi := deepPortRange(ScanConfig{DeepPortLo: 8000, DeepPortHi: 9000})
	if lo != 8000 || hi != 9000 {
		t.Errorf("narrowed deep range wrong: %d-%d", lo, hi)
	}
	lo, hi = deepPortRange(ScanConfig{})
	if lo != 1 || hi != 65535 {
		t.Errorf("default deep range should be full: %d-%d", lo, hi)
	}
}
