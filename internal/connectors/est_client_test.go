// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package connectors

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"kryptkeeper/internal/est"
)

// W13-03: EST client against our real internal/est server.

func TestESTClientEnrollsAgainstRealServer(t *testing.T) {
	engine, caID := upstreamCAEngine(t)
	var sawAuth bool
	// The client's Basic credential is a real EST user on our server
	// (W20-14), allowed names under .example.com, over TLS.
	hash, err := bcrypt.GenerateFromPassword([]byte("est-pass"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	estSrv := est.NewServer(engine, caID)
	if err := estSrv.WithBasicUsers([]est.User{{Username: "est-user", BcryptHash: string(hash), AllowedDNSSuffixes: []string{".example.com"}}}); err != nil {
		t.Fatal(err)
	}
	inner := estSrv.Handler()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if user, pass, ok := r.BasicAuth(); ok && user == "est-user" && pass == "est-pass" {
			sawAuth = true
		}
		inner.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	c := NewESTClient("est-1", ESTClientConfig{BaseURL: srv.URL, Username: "est-user", Password: "est-pass"}, srv.Client())
	if h := c.Health(context.Background()); h.Status != "healthy" {
		t.Fatalf("health: %+v", h)
	}
	res, err := c.Issue(context.Background(), IssueRequest{CSRPEM: testCSRPEM(t, "legacy-est.example.com")})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	block, _ := pem.Decode([]byte(res.CertificatePEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || cert.Subject.CommonName != "legacy-est.example.com" {
		t.Fatalf("issued cert: %v %v", cert, err)
	}
	if len(res.FingerprintSHA256) != 64 || !sawAuth {
		t.Fatalf("fingerprint/auth: %q auth=%v", res.FingerprintSHA256, sawAuth)
	}
}

// TestMalformedResponseErrorsClearly is W19-14's update of what was
// TestEnvelopedResponseErrorsClearly: parseCertsOnlyResponse now falls back
// to a real PKCS#7 parse (go.mozilla.org/pkcs7 is no longer gated), so a
// well-formed PKCS#7 certs-only body succeeds -- this asserts that a body
// which is neither a bare certificate nor a parseable PKCS#7 structure
// still errors clearly instead of mis-parsing.
func TestMalformedResponseErrorsClearly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(base64.StdEncoding.EncodeToString([]byte{0x30, 0x80, 0x06, 0x09, 0x2a})))
	}))
	t.Cleanup(srv.Close)
	c := NewESTClient("est-x", ESTClientConfig{BaseURL: srv.URL}, srv.Client())
	_, err := c.Issue(context.Background(), IssueRequest{CSRPEM: testCSRPEM(t, "x")})
	if err == nil || !strings.Contains(err.Error(), "neither a bare certificate nor a parseable PKCS#7") {
		t.Fatalf("malformed response must error clearly: %v", err)
	}
}

// TestESTClientRequestBodyEndsWithNewline: a single-line base64 body with no
// trailing newline is refused by libest's estserver (W27-10 live finding); the
// body must still decode with the plain TrimSpace + StdEncoding path our own
// server uses.
func TestESTClientRequestBodyEndsWithNewline(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		got = string(raw)
		http.Error(w, "stop here", http.StatusTeapot)
	}))
	t.Cleanup(srv.Close)
	c := NewESTClient("est-nl", ESTClientConfig{BaseURL: srv.URL}, srv.Client())
	_, _ = c.Issue(context.Background(), IssueRequest{CSRPEM: testCSRPEM(t, "nl.example.com")})
	if !strings.HasSuffix(got, "\n") || strings.Contains(strings.TrimSuffix(got, "\n"), "\n") {
		t.Fatalf("body must be one base64 run followed by exactly one newline, got %q", got)
	}
	if _, err := base64.StdEncoding.DecodeString(strings.TrimSpace(got)); err != nil {
		t.Fatalf("body is not decodable by TrimSpace+StdEncoding: %v", err)
	}
}
