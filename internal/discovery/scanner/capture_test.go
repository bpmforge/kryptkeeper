// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

func listenLocal(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func portOf(l net.Listener) int { return l.Addr().(*net.TCPAddr).Port }

func captureOne(t *testing.T, port int) DiscoveredEndpoint {
	t.Helper()
	s := New(ScanConfig{Timeout: 3 * time.Second})
	return s.scanEndpointOnce(context.Background(), fmt.Sprintf("127.0.0.1:%d", port))
}

func hasFindingPrefix(ep DiscoveredEndpoint, code string) bool {
	return slices.ContainsFunc(ep.Findings, func(f string) bool { return f == code || strings.HasPrefix(f, code+":") })
}

func TestClosedPortIsNotReachable(t *testing.T) {
	l := listenLocal(t)
	port := portOf(l)
	l.Close()
	ep := captureOne(t, port)
	if ep.Error == "" || ep.Reachable || len(ep.Findings) != 0 {
		t.Fatalf("closed port: want error, not reachable, no findings; got %+v", ep)
	}
}

func TestPlainHTTPServerIsReachableAndNotTLS(t *testing.T) {
	l := listenLocal(t)
	go func() {
		_ = http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "hi") }))
	}() // test server; Serve returns when the listener closes
	ep := captureOne(t, portOf(l))
	if !ep.Reachable {
		t.Fatalf("plain HTTP listener must be reachable: %+v", ep)
	}
	if !hasFindingPrefix(ep, FindingNotTLS) {
		t.Fatalf("want %s finding, got %v (error %q)", FindingNotTLS, ep.Findings, ep.Error)
	}
	if len(ep.Certs) != 0 {
		t.Fatalf("no certs expected: %+v", ep.Certs)
	}
}

func TestSilentListenerIsHandshakeFailed(t *testing.T) {
	l := listenLocal(t)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close() // accepts, then hangs up without speaking TLS
		}
	}()
	ep := captureOne(t, portOf(l))
	if !ep.Reachable || !hasFindingPrefix(ep, FindingTLSHandshakeFailed) {
		t.Fatalf("want reachable + %s, got %+v", FindingTLSHandshakeFailed, ep)
	}
	if ep.Error == "" {
		t.Fatal("handshake failure must keep Error set")
	}
}

func TestScanStatusReflectsOpenButFailedEndpoints(t *testing.T) {
	plain := listenLocal(t)
	go func() { _ = http.Serve(plain, http.NotFoundHandler()) }() // test server; Serve returns when the listener closes
	closed := listenLocal(t)
	closedPort := portOf(closed)
	closed.Close()

	s := New(ScanConfig{Targets: []string{
		fmt.Sprintf("127.0.0.1:%d", portOf(plain)), fmt.Sprintf("127.0.0.1:%d", closedPort),
	}, Timeout: 3 * time.Second})
	res := s.Scan(context.Background(), "j")
	if res.Status != "completed_with_errors" {
		t.Fatalf("status = %q, want completed_with_errors", res.Status)
	}
	if res.Reachable != 1 || res.Unreachable != 1 || res.ReachableFailed != 1 {
		t.Fatalf("counts reachable=%d unreachable=%d reachableFailed=%d", res.Reachable, res.Unreachable, res.ReachableFailed)
	}

	onlyClosed := New(ScanConfig{Targets: []string{fmt.Sprintf("127.0.0.1:%d", closedPort)}, Timeout: 3 * time.Second}).Scan(context.Background(), "j2")
	if onlyClosed.Status != "failed" {
		t.Fatalf("nothing reachable: status = %q, want failed", onlyClosed.Status)
	}
}

func legacyServerCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "legacy.test"},
		DNSNames: []string{"legacy.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func serveTLS(t *testing.T, l net.Listener, cfg *tls.Config) {
	t.Helper()
	tl := tls.NewListener(l, cfg)
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.(*tls.Conn).Handshake() // outcome irrelevant to the server side of the test
			}()
		}
	}()
}

func TestTLS10OnlyServerYieldsDeprecatedFindingAndCert(t *testing.T) {
	l := listenLocal(t)
	serveTLS(t, l, &tls.Config{
		Certificates: []tls.Certificate{legacyServerCert(t)},
		MinVersion:   tls.VersionTLS10, MaxVersion: tls.VersionTLS10,
	})
	ep := captureOne(t, portOf(l))
	if !slices.Contains(ep.Findings, FindingDeprecatedTLS+": TLSv1.0") {
		t.Fatalf("want %s: TLSv1.0, got %v (error %q)", FindingDeprecatedTLS, ep.Findings, ep.Error)
	}
	if ep.Error != "" || !ep.Reachable {
		t.Fatalf("a legacy server is a finding, not a failure: %+v", ep)
	}
	if ep.TLSVersion != "TLSv1.0" || len(ep.Certs) != 1 || !ep.Certs[0].Served {
		t.Fatalf("legacy handshake should still capture the served cert: version=%q certs=%d", ep.TLSVersion, len(ep.Certs))
	}
}

// fakeServerHello answers any ClientHello with a bare ServerHello whose
// version is v, then hangs up: enough for the probe, which never completes a
// handshake.
func fakeServerHello(t *testing.T, l net.Listener, v uint16) {
	t.Helper()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second)) // bound the fake
				hdr := make([]byte, 5)
				if _, err := io.ReadFull(c, hdr); err != nil {
					return
				}
				if _, err := io.CopyN(io.Discard, c, int64(binary.BigEndian.Uint16(hdr[3:5]))); err != nil {
					return
				}
				body := []byte{0x02, 0, 0, 38, byte(v >> 8), byte(v)}
				body = append(body, make([]byte, 32+1+2+1)...) // random, empty session id, suite, compression
				rec := []byte{0x16, byte(v >> 8), byte(v), byte(len(body) >> 8), byte(len(body))}
				_, _ = c.Write(append(rec, body...)) // fake peer; a failed write just fails the probe under test
			}()
		}
	}()
}

func TestRawServerHelloProbeDetectsLegacyVersions(t *testing.T) {
	for _, tc := range []struct {
		v    uint16
		want string
	}{{0x0301, "TLSv1.0"}, {0x0302, "TLSv1.1"}, {0x0300, "SSLv3"}} {
		l := listenLocal(t)
		fakeServerHello(t, l, tc.v)
		ep := captureOne(t, portOf(l))
		want := FindingDeprecatedTLS + ": " + tc.want
		if !slices.Contains(ep.Findings, want) {
			t.Errorf("version %#04x: want finding %q, got %v (error %q)", tc.v, want, ep.Findings, ep.Error)
		}
		if ep.Error != "" || len(ep.Certs) != 0 || ep.TLSVersion != tc.want {
			t.Errorf("version %#04x: want finding-only endpoint, got %+v", tc.v, ep)
		}
	}
}

func TestProbeIgnoresModernServerHelloAndAlerts(t *testing.T) {
	l := listenLocal(t)
	fakeServerHello(t, l, 0x0303)
	if v, ok := probeLegacyServerHello(context.Background(), "127.0.0.1", portOf(l), time.Second); ok {
		t.Fatalf("a TLS 1.2 ServerHello is not legacy, got %#04x", v)
	}
	l2 := listenLocal(t)
	go func() {
		for {
			c, err := l2.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte{0x15, 3, 1, 0, 2, 2, 70}) // protocol_version alert; fake peer
			c.Close()
		}
	}()
	if _, ok := probeLegacyServerHello(context.Background(), "127.0.0.1", portOf(l2), time.Second); ok {
		t.Fatal("an alert is not a ServerHello")
	}
}

func TestModernServerRecordsNoFindings(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "modern.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	l := listenLocal(t)
	serveTLS(t, l, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	ep := captureOne(t, portOf(l))
	if ep.Error != "" || len(ep.Findings) != 0 || len(ep.Certs) != 1 || !ep.Reachable {
		t.Fatalf("modern TLS server: want clean capture, got %+v", ep)
	}
}

func TestCapturedEndpointCarriesLowConfidenceFingerprint(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "fp.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	l := listenLocal(t)
	serveTLS(t, l, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	ep := captureOne(t, portOf(l))
	if ep.Fingerprint == nil || ep.Fingerprint.Confidence != ConfidenceLow || ep.Fingerprint.Tech != TechUnknown {
		t.Fatalf("a TLS service on an unknown port must fingerprint low/unknown, got %+v", ep.Fingerprint)
	}
	if ep.RecommendedInstallMode != "" {
		t.Fatalf("low confidence must not recommend, got %q", ep.RecommendedInstallMode)
	}
}

// negativeSerialCert returns a self-signed certificate whose serial number is
// negative, as SQL Server's default certificate is. x509.CreateCertificate
// refuses to make one, so a valid certificate is patched (serial sign bit set)
// and re-signed.
func negativeSerialCert(t *testing.T, cn string) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(5), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	var outer struct {
		TBS asn1.RawValue
		Alg asn1.RawValue
		Sig asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &outer); err != nil {
		t.Fatal(err)
	}
	tbs := append([]byte(nil), outer.TBS.FullBytes...)
	hdr := len(tbs) - len(outer.TBS.Bytes)
	// version [0] EXPLICIT INTEGER (5 bytes), then the serial INTEGER 02 01 05.
	if tbs[hdr+5] != 0x02 || tbs[hdr+6] != 0x01 {
		t.Fatalf("unexpected TBS layout: % x", tbs[hdr:hdr+10])
	}
	tbs[hdr+7] |= 0x80
	digest := sha256.Sum256(tbs)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	patched, err := asn1.Marshal(struct {
		TBS asn1.RawValue
		Alg asn1.RawValue
		Sig asn1.BitString
	}{asn1.RawValue{FullBytes: tbs}, outer.Alg, asn1.BitString{Bytes: sig, BitLength: len(sig) * 8}})
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{patched}, PrivateKey: key}
}

// SQL Server's default certificate has a negative serial number. The scanner
// must still record it (W34-20: every default SQL Server failed the handshake
// before go.mod enabled x509negativeserial).
func TestNegativeSerialCertificateIsCaptured(t *testing.T) {
	l := listenLocal(t)
	serveTLS(t, l, &tls.Config{Certificates: []tls.Certificate{negativeSerialCert(t, "SSL_Self_Signed_Fallback")}})
	ep := captureOne(t, portOf(l))
	if ep.Error != "" || len(ep.Certs) != 1 || ep.Certs[0].CommonName != "SSL_Self_Signed_Fallback" {
		t.Fatalf("negative-serial certificate not captured: %+v", ep)
	}
	if ep.Certs[0].SerialNumber != "-123" {
		t.Fatalf("serial = %q", ep.Certs[0].SerialNumber)
	}
	if fp := ep.Fingerprint; fp == nil || fp.Tech != "mssql" {
		t.Fatalf("the SQL Server default cert should fingerprint as mssql: %+v", fp)
	}
}
