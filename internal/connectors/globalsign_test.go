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
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// W36-09: GlobalSign Atlas connector against a TLS fixture that demands a
// client certificate, pinning OUR request shapes.

const (
	gsSecret = "GS-API-SECRET-0123456789abcdef0123456789abcdef"
	gsToken  = "GS-BEARER-TOKEN"
)

type gsFixture struct {
	t         *testing.T
	srv       *httptest.Server
	caPEM     string // server cert, pinned via CACertPEM
	cliCert   string
	cliKey    string
	csrPEM    string
	leafPEM   string
	rootPEM   string
	pending   int // number of 202 answers before ISSUED
	polls     int
	issueBody map[string]any
	issueCode int
	patchPath []string
	patchBody map[string]string
	patchCode map[string]int // path -> status override
	policy    int
	listing   map[string]string // stats kind -> JSON
	paths     []string
}

func gsPEM(typ string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}))
}

func newGSFixture(t *testing.T) *gsFixture {
	t.Helper()
	gen := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	f := &gsFixture{t: t, issueCode: 201, policy: 200, patchCode: map[string]int{}, listing: map[string]string{}}
	caKey, leafKey, cliKey := gen(), gen(), gen()
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Atlas CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(0xABCDEF01), Subject: pkix.Name{CommonName: "svc.example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	f.leafPEM, f.rootPEM = gsPEM("CERTIFICATE", leafDER), gsPEM("CERTIFICATE", caDER)
	cliTmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "kk-client"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	cliDER, _ := x509.CreateCertificate(rand.Reader, cliTmpl, cliTmpl, &cliKey.PublicKey, cliKey)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(cliKey)
	f.cliCert, f.cliKey = gsPEM("CERTIFICATE", cliDER), gsPEM("PRIVATE KEY", keyDER)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: "svc.example.com", Organization: []string{"Acme"}, Country: []string{"SE"}},
		DNSNames:    []string{"svc.example.com", "alt.example.com"},
		IPAddresses: []net.IP{net.ParseIP("10.0.0.5")},
	}, leafKey)
	if err != nil {
		t.Fatal(err)
	}
	f.csrPEM = gsPEM("CERTIFICATE REQUEST", csrDER)

	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(f.handle))
	f.srv.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	f.caPEM = gsPEM("CERTIFICATE", f.srv.Certificate().Raw)
	return f
}

func (f *gsFixture) handle(w http.ResponseWriter, r *http.Request) {
	f.paths = append(f.paths, r.Method+" "+r.URL.Path)
	if len(r.TLS.PeerCertificates) == 0 || r.TLS.PeerCertificates[0].Subject.CommonName != "kk-client" {
		http.Error(w, "no client cert", http.StatusUnauthorized)
		return
	}
	if r.URL.Path == "/v2/login" {
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		if r.Method != http.MethodPost || in["api_key"] != "k" || in["api_secret"] != gsSecret {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"description":"bad credentials"}`))
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"` + gsToken + `"}`))
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+gsToken {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v2/certificates":
		if r.Header.Get("Content-Type") != "application/json;charset=utf-8" {
			f.t.Errorf("content-type = %q", r.Header.Get("Content-Type"))
		}
		f.issueBody = map[string]any{}
		_ = json.NewDecoder(r.Body).Decode(&f.issueBody)
		if f.issueCode == 429 {
			w.Header().Set("Retry-After", "7")
		}
		if f.issueCode != 201 {
			w.WriteHeader(f.issueCode)
			_, _ = w.Write([]byte(`{"description":"rejected"}`))
			return
		}
		w.Header().Set("Location", "https://other.invalid/v2/certificates/12345")
		w.WriteHeader(201)
	case r.Method == http.MethodGet && r.URL.Path == "/v2/certificates/12345":
		f.polls++
		if f.polls <= f.pending {
			w.WriteHeader(202)
			return
		}
		b, _ := json.Marshal(map[string]any{"certificate": f.leafPEM, "status": "ISSUED"})
		_, _ = w.Write(b)
	case r.Method == http.MethodGet && r.URL.Path == "/v2/trustchain":
		b, _ := json.Marshal([]string{f.rootPEM})
		_, _ = w.Write(b)
	case r.Method == http.MethodGet && r.URL.Path == "/v2/validationpolicy":
		w.WriteHeader(f.policy)
		_, _ = w.Write([]byte(`{}`))
	case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/v2/certificates/"):
		f.patchPath = append(f.patchPath, r.URL.Path)
		f.patchBody = map[string]string{}
		_ = json.NewDecoder(r.Body).Decode(&f.patchBody)
		if code := f.patchCode[r.URL.Path]; code != 0 {
			w.WriteHeader(code)
			_, _ = w.Write([]byte(`{"description":"conflict"}`))
			return
		}
		w.WriteHeader(204)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v2/stats/"):
		kind := strings.TrimPrefix(r.URL.Path, "/v2/stats/")
		q := r.URL.Query()
		if q.Get("from") == "" || q.Get("to") == "" || q.Get("page") != "1" || q.Get("per_page") != "100" {
			f.t.Errorf("stats query = %v", q)
		}
		body := f.listing[kind]
		if body == "" {
			body = "[]"
		}
		_, _ = w.Write([]byte(body))
	case r.Method == http.MethodGet && r.URL.Path == "/v2/certificates/111":
		b, _ := json.Marshal(map[string]any{"certificate": f.leafPEM, "status": "ISSUED"})
		_, _ = w.Write(b)
	case r.Method == http.MethodGet && r.URL.Path == "/v2/certificates/222":
		b, _ := json.Marshal(map[string]any{"certificate": f.rootPEM, "status": "REVOKED"})
		_, _ = w.Write(b)
	default:
		http.NotFound(w, r)
	}
}

func (f *gsFixture) connector() *GlobalSignConnector {
	return NewGlobalSignConnector("gs", GlobalSignConfig{
		BaseURL: f.srv.URL + "/v2", APIKey: "k", APISecret: gsSecret,
		ClientCertPEM: f.cliCert, ClientKeyPEM: f.cliKey, CACertPEM: f.caPEM,
		PollAttempts: 4, PollInterval: time.Millisecond,
	}, testClient(f.cliCert, f.cliKey, f.caPEM))
}

func TestGlobalSignIssueSuccessBodyAndChain(t *testing.T) {
	f := newGSFixture(t)
	f.pending = 1 // one 202 first
	res, err := f.connector().Issue(context.Background(), IssueRequest{CSRPEM: f.csrPEM})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if f.polls != 2 {
		t.Errorf("polls = %d, want 2 (202 then ISSUED)", f.polls)
	}
	if strings.Count(res.CertificatePEM, "BEGIN CERTIFICATE") != 2 || !strings.HasPrefix(res.CertificatePEM, f.leafPEM) {
		t.Errorf("bundle should be leaf then chain:\n%s", res.CertificatePEM)
	}
	if len(res.FingerprintSHA256) != 64 {
		t.Errorf("fingerprint = %q", res.FingerprintSHA256)
	}
	b := f.issueBody
	if b["public_key"] != f.csrPEM {
		t.Error("public_key must carry the CSR PEM")
	}
	sub := b["subject_dn"].(map[string]any)
	if sub["common_name"] != "svc.example.com" || sub["organization"] != "Acme" || sub["country"] != "SE" {
		t.Errorf("subject_dn = %v", sub)
	}
	san := b["san"].(map[string]any)
	if len(san["dns_names"].([]any)) != 2 || san["ip_addresses"].([]any)[0] != "10.0.0.5" {
		t.Errorf("san = %v", san)
	}
	v := b["validity"].(map[string]any)
	nb, na := v["not_before"].(float64), v["not_after"].(float64)
	if d := (na - nb) / 86400; d < 89.9 || d > 90.1 {
		t.Errorf("validity days = %v, want default 90", d)
	}
	// Location host is ignored: every call went to the fixture.
	for _, p := range f.paths {
		if strings.Contains(p, "other.invalid") {
			t.Errorf("followed hostile Location: %s", p)
		}
	}
}

func TestGlobalSignIssuePendingExhausted(t *testing.T) {
	f := newGSFixture(t)
	f.pending = 100
	_, err := f.connector().Issue(context.Background(), IssueRequest{CSRPEM: f.csrPEM})
	if err == nil || !strings.Contains(err.Error(), "still pending") {
		t.Fatalf("want pending error, got %v", err)
	}
}

func TestGlobalSignIssueErrorsDoNotLeakSecret(t *testing.T) {
	f := newGSFixture(t)
	f.issueCode = 422
	c := f.connector()
	_, err := c.Issue(context.Background(), IssueRequest{CSRPEM: f.csrPEM})
	if err == nil || !strings.Contains(err.Error(), "422") {
		t.Fatalf("want 422 error, got %v", err)
	}
	// Neither the token nor the secret may appear in surfaced errors.
	if strings.Contains(err.Error(), gsToken) || strings.Contains(err.Error(), gsSecret) {
		t.Error("bearer token leaked")
	}
	bad := NewGlobalSignConnector("gs", GlobalSignConfig{BaseURL: f.srv.URL + "/v2", APIKey: "wrong", APISecret: gsSecret,
		ClientCertPEM: f.cliCert, ClientKeyPEM: f.cliKey, CACertPEM: f.caPEM}, testClient(f.cliCert, f.cliKey, f.caPEM))
	_, err = bad.Issue(context.Background(), IssueRequest{CSRPEM: f.csrPEM})
	if err == nil || !strings.Contains(err.Error(), "login failed") || strings.Contains(err.Error(), gsSecret) {
		t.Fatalf("login error = %v", err)
	}
}

func TestGlobalSignRateLimit(t *testing.T) {
	f := newGSFixture(t)
	f.issueCode = 429
	_, err := f.connector().Issue(context.Background(), IssueRequest{CSRPEM: f.csrPEM})
	var rl *RateLimitError
	if !errors.As(err, &rl) || rl.RetryAfter != 7*time.Second || rl.Reason != "upstream_429" {
		t.Fatalf("want RateLimitError 7s, got %v", err)
	}
}

func TestGlobalSignRejectsBadCSRAndMissingClientCert(t *testing.T) {
	f := newGSFixture(t)
	if _, err := f.connector().Issue(context.Background(), IssueRequest{CSRPEM: "nope"}); err == nil {
		t.Error("bad CSR must fail")
	}
	// No client cert: the fixture demands one, so the TLS handshake fails.
	c := NewGlobalSignConnector("gs", GlobalSignConfig{BaseURL: f.srv.URL + "/v2", APIKey: "k", APISecret: gsSecret, CACertPEM: f.caPEM}, testClient("", "", f.caPEM))
	if h := c.Health(context.Background()); h.Status != "degraded" {
		t.Errorf("health without client cert = %+v", h)
	}
	// Bad key PEM: error must not echo the key.
	bad := NewGlobalSignConnector("gs", GlobalSignConfig{APIKey: "k", APISecret: gsSecret,
		ClientCertPEM: f.cliCert, ClientKeyPEM: "-----BEGIN PRIVATE KEY-----\nSECRETKEYBYTES\n-----END PRIVATE KEY-----"}, testClient("", "", ""))
	h := bad.Health(context.Background())
	if h.Status != "degraded" || strings.Contains(h.Detail, "SECRETKEYBYTES") {
		t.Errorf("bad key health = %+v", h)
	}
}

func TestGlobalSignRevokeReasonsAndFallback(t *testing.T) {
	f := newGSFixture(t)
	c := f.connector()
	// 0xABCDEF01 = 2882400001
	if err := c.Revoke(context.Background(), RevokeRequest{SerialHex: "ABCDEF01", Reason: 1}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if f.patchPath[0] != "/v2/certificates/2882400001" || f.patchBody["revocation_reason"] != "keyCompromise" {
		t.Errorf("patch = %v %v", f.patchPath, f.patchBody)
	}
	if err := c.Revoke(context.Background(), RevokeRequest{SerialHex: "abcdef01", Reason: 2}); err != nil {
		t.Fatal(err)
	}
	if f.patchBody["revocation_reason"] != "unspecified" {
		t.Errorf("CA compromise should map to unspecified, got %v", f.patchBody)
	}
	// Decimal 404 falls back to the hex form.
	f.patchCode["/v2/certificates/2882400001"] = 404
	f.patchPath = nil
	if err := c.Revoke(context.Background(), RevokeRequest{SerialHex: "abcdef01", Reason: 5}); err != nil {
		t.Fatal(err)
	}
	if len(f.patchPath) != 2 || f.patchPath[1] != "/v2/certificates/abcdef01" || f.patchBody["revocation_reason"] != "cessationOfOperation" {
		t.Errorf("fallback = %v %v", f.patchPath, f.patchBody)
	}
}

func TestGlobalSignRevokeError(t *testing.T) {
	f := newGSFixture(t)
	f.patchCode["/v2/certificates/2882400001"] = 409
	err := f.connector().Revoke(context.Background(), RevokeRequest{SerialHex: "abcdef01"})
	if err == nil || !strings.Contains(err.Error(), "409") {
		t.Fatalf("want 409, got %v", err)
	}
	if err := f.connector().Revoke(context.Background(), RevokeRequest{SerialHex: "zz"}); err == nil {
		t.Error("non-hex serial must fail")
	}
}

func TestGlobalSignHealth(t *testing.T) {
	f := newGSFixture(t)
	c := f.connector()
	if h := c.Health(context.Background()); h.Status != "healthy" {
		t.Fatalf("healthy = %+v", h)
	}
	f.policy = 503
	if h := c.Health(context.Background()); h.Status != "degraded" || !strings.Contains(h.Detail, "503") {
		t.Fatalf("degraded = %+v", h)
	}
}

func TestGlobalSignListCertificates(t *testing.T) {
	f := newGSFixture(t)
	f.listing["issued"] = `[{"serial_number":"111","not_before":1,"not_after":2}]`
	f.listing["revoked"] = `[{"serial_number":"222","not_before":1,"not_after":2}]`
	recs, err := f.connector().ListCertificates(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 || recs[0].Revoked || !recs[1].Revoked {
		t.Fatalf("recs = %+v", recs)
	}
	for _, p := range f.paths {
		if strings.HasPrefix(p, "POST /v2/certificates") || strings.HasPrefix(p, "PATCH") || strings.HasPrefix(p, "DELETE") {
			t.Errorf("listing must be read-only, saw %s", p)
		}
	}
}
