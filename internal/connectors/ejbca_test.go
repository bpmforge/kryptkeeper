// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package connectors

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// W36-05: EJBCA REST connector against a TLS fixture that demands a client
// certificate, pinning OUR request shapes (method, escaped path, query, body).

const ejbcaTestSecret = "TOPSECRET-VENDOR-TOKEN"

type ejbcaPKI struct {
	caDER, leafDER      []byte
	clientCert, clientK string
	csrPEM              string
}

func ejbcaMakePKI(t *testing.T) ejbcaPKI {
	t.Helper()
	gen := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("key: %v", err)
		}
		return k
	}
	caKey, leafKey, cliKey := gen(), gen(), gen()
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Issuing CA", Organization: []string{"Acme, Inc"}, Country: []string{"SE"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0xABCDEF01), Subject: pkix.Name{CommonName: "svc.example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cliTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "kk-client"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	cliDER, err := x509.CreateCertificate(rand.Reader, cliTmpl, cliTmpl, &cliKey.PublicKey, cliKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(cliKey)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "svc.example.com"}}, leafKey)
	if err != nil {
		t.Fatal(err)
	}
	return ejbcaPKI{
		caDER: caDER, leafDER: leafDER,
		clientCert: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cliDER})),
		clientK:    string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
		csrPEM:     string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
	}
}

type ejbcaFixture struct {
	pki      ejbcaPKI
	srv      *httptest.Server
	enroll   func(w http.ResponseWriter, body map[string]any)
	lastBody map[string]any
	revPath  string
	revQuery string
	revCode  int
	status   int
}

func newEJBCAFixture(t *testing.T) *ejbcaFixture {
	t.Helper()
	f := &ejbcaFixture{pki: ejbcaMakePKI(t), revCode: 200, status: 200}
	b64 := base64.StdEncoding.EncodeToString
	f.enroll = func(w http.ResponseWriter, _ map[string]any) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"certificate":       b64(f.pki.leafDER),
			"certificate_chain": []string{b64(f.pki.leafDER), b64(f.pki.caDER)},
			"response_format":   "DER",
		})
	}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || r.TLS.PeerCertificates[0].Subject.CommonName != "kk-client" {
			http.Error(w, "no client cert", http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/ejbca/ejbca-rest-api/v1/certificate/status":
			w.WriteHeader(f.status)
			_, _ = w.Write([]byte(`{"status":"OK","version":"1.0","revision":"ALPHA"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/ejbca/ejbca-rest-api/v1/certificate/pkcs10enroll":
			if r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("content-type = %q", r.Header.Get("Content-Type"))
			}
			body := map[string]any{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.lastBody = body
			f.enroll(w, body)
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/revoke"):
			f.revPath, f.revQuery = r.URL.EscapedPath(), r.URL.RawQuery
			w.WriteHeader(f.revCode)
			if f.revCode == 200 {
				_, _ = w.Write([]byte(`{"revoked":true,"message":"Successfully revoked"}`))
			} else {
				_, _ = w.Write([]byte(`{"error_message":"nope ` + ejbcaTestSecret + `"}`))
			}
		default:
			http.NotFound(w, r)
		}
	}))
	f.srv.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

func (f *ejbcaFixture) connector() *EJBCAConnector {
	srvCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})
	return NewEJBCAConnector("ej-1", EJBCAConfig{
		BaseURL: f.srv.URL + "/ejbca/ejbca-rest-api", CertificateProfileName: "ENDUSER",
		EndEntityProfileName: "EMPTY", CertificateAuthorityName: "ManagementCA",
		ClientCertPEM: f.pki.clientCert, ClientKeyPEM: f.pki.clientK, CACertPEM: string(srvCert),
	}, testClient(f.pki.clientCert, f.pki.clientK, string(srvCert)))
}

func TestEJBCAIssueShapeAndChain(t *testing.T) {
	f := newEJBCAFixture(t)
	res, err := f.connector().Issue(context.Background(), IssueRequest{CSRPEM: f.pki.csrPEM})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	for k, want := range map[string]any{
		"certificate_request": f.pki.csrPEM, "certificate_profile_name": "ENDUSER",
		"end_entity_profile_name": "EMPTY", "certificate_authority_name": "ManagementCA",
		"include_chain": true, "response_format": "DER",
	} {
		if f.lastBody[k] != want {
			t.Errorf("body[%s] = %v, want %v", k, f.lastBody[k], want)
		}
	}
	if u, _ := f.lastBody["username"].(string); !strings.HasPrefix(u, "kk-") || len(u) != 3+16 {
		t.Errorf("username = %q", u)
	}
	if p, _ := f.lastBody["password"].(string); len(p) < 32 {
		t.Errorf("enrollment code too short: %d", len(p))
	}
	blocks := strings.Count(res.CertificatePEM, "BEGIN CERTIFICATE")
	if blocks != 2 {
		t.Fatalf("want leaf+CA (echoed leaf deduped), got %d blocks", blocks)
	}
	first, _ := pem.Decode([]byte(res.CertificatePEM))
	if string(first.Bytes) != string(f.pki.leafDER) {
		t.Fatal("leaf must come first")
	}
	if len(res.FingerprintSHA256) != 64 {
		t.Fatalf("fingerprint = %q", res.FingerprintSHA256)
	}
}

func TestEJBCAUsernameStableAndPasswordFresh(t *testing.T) {
	f := newEJBCAFixture(t)
	c := f.connector()
	_, _ = c.Issue(context.Background(), IssueRequest{CSRPEM: f.pki.csrPEM})
	u1, p1 := f.lastBody["username"], f.lastBody["password"]
	_, _ = c.Issue(context.Background(), IssueRequest{CSRPEM: f.pki.csrPEM})
	if f.lastBody["username"] != u1 || f.lastBody["password"] == p1 {
		t.Fatal("username must be stable per CSR, password fresh per request")
	}
}

func TestEJBCAIssueRefusesGarbage(t *testing.T) {
	f := newEJBCAFixture(t)
	c := f.connector()
	if _, err := c.Issue(context.Background(), IssueRequest{CSRPEM: "nope"}); err == nil {
		t.Fatal("bad CSR must be refused")
	}
	f.enroll = func(w http.ResponseWriter, _ map[string]any) {
		_, _ = w.Write([]byte(`{"certificate":"bm90IGEgY2VydA=="}`))
	}
	if _, err := c.Issue(context.Background(), IssueRequest{CSRPEM: f.pki.csrPEM}); err == nil {
		t.Fatal("unparseable certificate must be refused")
	}
	f.enroll = func(w http.ResponseWriter, _ map[string]any) { _, _ = w.Write([]byte(`{}`)) }
	if _, err := c.Issue(context.Background(), IssueRequest{CSRPEM: f.pki.csrPEM}); err == nil {
		t.Fatal("missing certificate must be refused")
	}
}

func TestEJBCA4xxDoesNotLeakSecret(t *testing.T) {
	f := newEJBCAFixture(t)
	f.enroll = func(w http.ResponseWriter, _ map[string]any) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error_code":400,"error_message":"profile not found"}`))
	}
	c := f.connector()
	_, err := c.Issue(context.Background(), IssueRequest{CSRPEM: f.pki.csrPEM})
	if err == nil || !strings.Contains(err.Error(), "HTTP 400") {
		t.Fatalf("err = %v", err)
	}
	for _, s := range []string{f.pki.clientK, "PRIVATE KEY"} {
		if strings.Contains(err.Error(), s) {
			t.Fatal("error leaks key material")
		}
	}
	if h := c.Health(context.Background()); h.Status != "degraded" || !strings.Contains(h.Detail, "last issue error") {
		t.Fatalf("health = %+v", h)
	}
}

func TestEJBCA429CarriesRetryAfter(t *testing.T) {
	f := newEJBCAFixture(t)
	f.enroll = func(w http.ResponseWriter, _ map[string]any) {
		w.Header().Set("Retry-After", "42")
		w.WriteHeader(http.StatusTooManyRequests)
	}
	_, err := f.connector().Issue(context.Background(), IssueRequest{CSRPEM: f.pki.csrPEM})
	var rl *RateLimitError
	if !errors.As(err, &rl) || rl.RetryAfter != 42*time.Second || rl.Reason != "upstream_429" {
		t.Fatalf("err = %v", err)
	}
}

func TestEJBCARevokeSuccessShape(t *testing.T) {
	f := newEJBCAFixture(t)
	leaf := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.pki.leafDER}))
	err := f.connector().Revoke(context.Background(), RevokeRequest{SerialHex: "abcdef01", CertificatePEM: leaf, Reason: 1})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	// Issuer DN is one escaped path segment; commas are percent-encoded.
	want := "/ejbca/ejbca-rest-api/v1/certificate/CN=Test%20Issuing%20CA%2CO=Acme%5C%2C%20Inc%2CC=SE/abcdef01/revoke"
	if f.revPath != want {
		t.Fatalf("path = %s\nwant   %s", f.revPath, want)
	}
	if f.revQuery != "reason=KEY_COMPROMISE" {
		t.Fatalf("query = %q", f.revQuery)
	}
	if err := f.connector().Revoke(context.Background(), RevokeRequest{CertificatePEM: leaf, Reason: 99}); err != nil {
		t.Fatal(err)
	}
	if f.revQuery != "reason=UNSPECIFIED" || !strings.HasSuffix(f.revPath, "/abcdef01/revoke") {
		t.Fatalf("unknown reason / serial fallback: %s %s", f.revPath, f.revQuery)
	}
}

func TestEJBCARevokeErrors(t *testing.T) {
	f := newEJBCAFixture(t)
	c := f.connector()
	if err := c.Revoke(context.Background(), RevokeRequest{SerialHex: "01"}); err == nil {
		t.Fatal("revoke without certificate PEM must refuse")
	}
	f.revCode = http.StatusNotFound
	leaf := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.pki.leafDER}))
	err := c.Revoke(context.Background(), RevokeRequest{CertificatePEM: leaf})
	if err == nil || !strings.Contains(err.Error(), "HTTP 404") {
		t.Fatalf("err = %v", err)
	}
}

func TestEJBCAHealth(t *testing.T) {
	f := newEJBCAFixture(t)
	c := f.connector()
	if h := c.Health(context.Background()); h.Status != "healthy" {
		t.Fatalf("health = %+v", h)
	}
	f.status = http.StatusServiceUnavailable
	if h := c.Health(context.Background()); h.Status != "degraded" {
		t.Fatalf("health = %+v", h)
	}
}

func TestEJBCABadClientPEMDegradesWithoutLeak(t *testing.T) {
	f := newEJBCAFixture(t)
	c := NewEJBCAConnector("ej-2", EJBCAConfig{BaseURL: f.srv.URL, ClientCertPEM: f.pki.clientCert, ClientKeyPEM: "garbage-" + ejbcaTestSecret}, testClient("", "", ""))
	h := c.Health(context.Background())
	if h.Status != "degraded" || strings.Contains(h.Detail, ejbcaTestSecret) {
		t.Fatalf("health = %+v", h)
	}
	if c.Type() != "ejbca" || c.Origin() != "synced" || c.ID() != "ej-2" {
		t.Fatal("identity accessors")
	}
}

func TestEJBCAWithoutClientCertIsRejected(t *testing.T) {
	// Proves the fixture (and so the happy-path tests) really exercise mTLS.
	f := newEJBCAFixture(t)
	srvCert := x509.NewCertPool()
	srvCert.AddCert(f.srv.Certificate())
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: srvCert, MinVersion: tls.VersionTLS12}}}
	if _, err := cl.Get(f.srv.URL + "/ejbca/ejbca-rest-api/v1/certificate/status"); err == nil {
		t.Fatal("server must require a client certificate")
	}
}
