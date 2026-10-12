// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package connectors

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
	"kryptkeeper/internal/wstep"
)

// W13-01: the WSTEP client proven against our OWN MS-WSTEP server
// backed by a real CA engine — a real protocol conversation, not
// hand-mocked XML.

func wstepTestServer(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()
	dir := t.TempDir()
	keys, err := keystore.NewSoftwareStore(dir, []byte("test-wstep-client-passphrase!!!!"))
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	engine := ca.NewEngine(keys, ca.NewMemStore())
	root, err := engine.CreateRootCA("Client Test Root", pkix.Name{CommonName: "Client Test Root"},
		keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	// Basic auth below is the client's transport credential; our server
	// binds the subject to whoever authenticated (W20-08), so stand in for
	// that with the identity the CSR also names.
	asSvc := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(wstep.WithIdentity(r.Context(), wstep.Identity{
				Method: "kerberos", Principal: "svc-enroll@CORP.EXAMPLE",
				Subject: pkix.Name{CommonName: "app.corp.example"},
			})))
		})
	}
	inner := wstep.NewServer(engine, root.ID).WithAuthenticator(asSvc).Handler()
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// CES-style transport auth: Basic over TLS.
		user, pass, ok := r.BasicAuth()
		if !ok || user != "svc-enroll" || pass != "hunter2" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		raw, _ := io.ReadAll(r.Body) // fixture: short in-memory bodies
		bodies = append(bodies, string(raw))
		r2 := r.Clone(r.Context())
		r2.Body = io.NopCloser(strings.NewReader(string(raw)))
		inner.ServeHTTP(w, r2)
	}))
	t.Cleanup(srv.Close)
	return srv, &bodies
}

func testCSRPEM(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func wstepClientFor(srv *httptest.Server) *WSTEPClient {
	return NewWSTEPClient("adcs-1", WSTEPClientConfig{
		EndpointURL: srv.URL, Username: "svc-enroll", Password: "hunter2",
		TemplateName: "KryptkeeperWebServer",
	}, srv.Client())
}

func TestWSTEPClientIssuesAgainstRealServer(t *testing.T) {
	srv, bodies := wstepTestServer(t)
	c := wstepClientFor(srv)

	res, err := c.Issue(context.Background(), IssueRequest{CSRPEM: testCSRPEM(t, "app.corp.example")})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	block, _ := pem.Decode([]byte(res.CertificatePEM))
	if block == nil {
		t.Fatal("result is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cert.Subject.CommonName != "app.corp.example" {
		t.Fatalf("issued CN %q", cert.Subject.CommonName)
	}
	if len(res.FingerprintSHA256) != 64 {
		t.Fatalf("fingerprint %q", res.FingerprintSHA256)
	}
	// The outbound envelope carried the WS-Trust action, the template
	// TokenType, and a base64 CSR token.
	sent := (*bodies)[0]
	for _, want := range []string{"enrollment/RST/wstep", "KryptkeeperWebServer", "BinarySecurityToken"} {
		if !strings.Contains(sent, want) {
			t.Fatalf("outbound envelope missing %q", want)
		}
	}
	if c.Origin() != "synced" || c.Type() != "adcs-wstep" {
		t.Fatalf("connector identity: %s/%s", c.Type(), c.Origin())
	}
}

func TestWSTEPClientSurfacesAuthAndFaults(t *testing.T) {
	srv, _ := wstepTestServer(t)

	// Wrong password → 401 named in the error.
	bad := NewWSTEPClient("adcs-1", WSTEPClientConfig{
		EndpointURL: srv.URL, Username: "svc-enroll", Password: "wrong",
	}, srv.Client())
	if _, err := bad.Issue(context.Background(), IssueRequest{CSRPEM: testCSRPEM(t, "x")}); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("auth failure must surface: %v", err)
	}

	// Garbage CSR → the server's SOAP fault text comes through.
	c := wstepClientFor(srv)
	badCSR := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte("junk")}))
	if _, err := c.Issue(context.Background(), IssueRequest{CSRPEM: badCSR}); err == nil || !strings.Contains(err.Error(), "SOAP fault") {
		t.Fatalf("fault must surface with reason: %v", err)
	}

	// Non-PEM input refused client-side.
	if _, err := c.Issue(context.Background(), IssueRequest{CSRPEM: "not pem"}); err == nil {
		t.Fatal("non-PEM CSR must be refused before any network call")
	}
}

func TestWSTEPClientHealth(t *testing.T) {
	srv, _ := wstepTestServer(t)
	c := wstepClientFor(srv)
	if h := c.Health(context.Background()); h.Status != "healthy" {
		t.Fatalf("reachable endpoint must be healthy: %+v", h)
	}
	srv.Close()
	if h := c.Health(context.Background()); h.Status != "degraded" || h.Detail == "" {
		t.Fatalf("dead endpoint must be degraded with detail: %+v", h)
	}
}
