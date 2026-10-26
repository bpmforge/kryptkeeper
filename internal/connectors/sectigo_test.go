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
	"sync/atomic"
	"testing"
	"time"
)

// W36-08: SCM connector against httptest fixtures pinning OUR request shapes.

const sectigoTestSecret = "TOPSECRET-SCM-PASSWORD"

type sectigoPKI struct {
	caDER, leafDER []byte
	csrPEM         string
}

func sectigoMakePKI(t *testing.T) sectigoPKI {
	t.Helper()
	gen := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	caKey, leafKey := gen(), gen()
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test SCM CA"},
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
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "svc.example.com"},
		DNSNames: []string{"svc.example.com", "alt.example.com"}, IPAddresses: []net.IP{net.ParseIP("10.0.0.5")},
	}, leafKey)
	if err != nil {
		t.Fatal(err)
	}
	return sectigoPKI{caDER: caDER, leafDER: leafDER,
		csrPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))}
}

func pemOf(ders ...[]byte) string {
	var sb strings.Builder
	for _, d := range ders {
		sb.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d}))
	}
	return sb.String()
}

type sectigoFixture struct {
	pki          sectigoPKI
	srv          *httptest.Server
	enrollBody   map[string]any
	enrollStatus int
	collectCalls atomic.Int32
	pendingFor   int32 // collect answers 404 this many times first
	collectBody  string
	collectQuery string
	listJSON     string
	revokePath   string
	revokeBody   map[string]any
	revokeStatus int
	typesStatus  int
	hdr          http.Header
}

func newSectigoFixture(t *testing.T) *sectigoFixture {
	t.Helper()
	f := &sectigoFixture{pki: sectigoMakePKI(t), enrollStatus: 200, revokeStatus: 204, typesStatus: 200}
	f.collectBody = pemOf(f.pki.caDER, f.pki.leafDER) // CA first on purpose: connector must reorder
	f.listJSON = `[{"sslId":4242,"serialNumber":"AB:CD:EF:01"}]`
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hdr = r.Header.Clone()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/ssl/v2/types":
			w.WriteHeader(f.typesStatus)
			_, _ = w.Write([]byte(`[{"id":9,"name":"DV","terms":[90,365]}]`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/ssl/v2/enroll":
			if r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("content-type = %q", r.Header.Get("Content-Type"))
			}
			f.enrollBody = map[string]any{}
			_ = json.NewDecoder(r.Body).Decode(&f.enrollBody)
			if f.enrollStatus == 429 {
				w.Header().Set("Retry-After", "7")
			}
			w.WriteHeader(f.enrollStatus)
			if f.enrollStatus == 200 {
				_, _ = w.Write([]byte(`{"sslId":4242,"renewId":"r"}`))
			} else {
				_, _ = w.Write([]byte(`{"code":-1,"description":"bad ` + sectigoTestSecret + `"}`))
			}
		case r.Method == http.MethodGet && r.URL.Path == "/api/ssl/v2/collect/4242":
			f.collectQuery = r.URL.RawQuery
			if f.collectCalls.Add(1) <= f.pendingFor {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"code":-1,"description":"not issued yet"}`))
				return
			}
			_, _ = w.Write([]byte(f.collectBody))
		case r.Method == http.MethodGet && r.URL.Path == "/api/ssl/v2":
			if got := r.URL.Query().Get("serialNumber"); got != "ABCDEF01" {
				t.Errorf("serialNumber filter = %q", got)
			}
			_, _ = w.Write([]byte(f.listJSON))
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/ssl/v2/revoke/"):
			f.revokePath = r.URL.Path
			f.revokeBody = map[string]any{}
			_ = json.NewDecoder(r.Body).Decode(&f.revokeBody)
			w.WriteHeader(f.revokeStatus)
			if f.revokeStatus >= 400 {
				_, _ = w.Write([]byte(`{"description":"nope ` + sectigoTestSecret + `"}`))
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *sectigoFixture) connector() *SectigoConnector {
	return NewSectigoConnector("sc-1", SectigoConfig{
		BaseURL: f.srv.URL, CustomerURI: "acme", OrgID: 12, CertType: 9, TermDays: 365,
		Login: "svc", Password: sectigoTestSecret,
		PollAttempts: 4, PollInterval: time.Millisecond,
	}, testClient("", "", ""))
}

func TestSectigoIssueShapeAndLeafFirst(t *testing.T) {
	f := newSectigoFixture(t)
	res, err := f.connector().Issue(context.Background(), IssueRequest{CSRPEM: f.pki.csrPEM})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	for k, want := range map[string]any{
		"orgId": float64(12), "certType": float64(9), "term": float64(365), "csr": f.pki.csrPEM,
		"subjAltNames": "svc.example.com,alt.example.com,10.0.0.5",
	} {
		if f.enrollBody[k] != want {
			t.Errorf("enroll[%s] = %v, want %v", k, f.enrollBody[k], want)
		}
	}
	if f.collectQuery != "format=x509" {
		t.Errorf("collect query = %q", f.collectQuery)
	}
	for h, want := range map[string]string{"Login": "svc", "Password": sectigoTestSecret, "Customeruri": "acme"} {
		if f.hdr.Get(h) != want {
			t.Errorf("header %s = %q", h, f.hdr.Get(h))
		}
	}
	first, _ := pem.Decode([]byte(res.CertificatePEM))
	if string(first.Bytes) != string(f.pki.leafDER) {
		t.Fatal("leaf must come first even when SCM lists the CA first")
	}
	if strings.Count(res.CertificatePEM, "BEGIN CERTIFICATE") != 2 || len(res.FingerprintSHA256) != 64 {
		t.Fatalf("bundle/fingerprint wrong: %q", res.FingerprintSHA256)
	}
}

func TestSectigoPendingThenIssued(t *testing.T) {
	f := newSectigoFixture(t)
	f.pendingFor = 2
	if _, err := f.connector().Issue(context.Background(), IssueRequest{CSRPEM: f.pki.csrPEM}); err != nil {
		t.Fatalf("issue: %v", err)
	}
	if got := f.collectCalls.Load(); got != 3 {
		t.Fatalf("collect calls = %d, want 3", got)
	}
}

func TestSectigoPendingExhaustedAndCtxCancel(t *testing.T) {
	f := newSectigoFixture(t)
	f.pendingFor = 100
	_, err := f.connector().Issue(context.Background(), IssueRequest{CSRPEM: f.pki.csrPEM})
	if err == nil || !strings.Contains(err.Error(), "not issued after 4 polls") {
		t.Fatalf("err = %v", err)
	}
	c := f.connector()
	c.cfg.PollInterval = time.Hour
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := c.Issue(ctx, IssueRequest{CSRPEM: f.pki.csrPEM}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want deadline, got %v", err)
	}
}

func TestSectigoErrorsHideSecret(t *testing.T) {
	f := newSectigoFixture(t)
	f.enrollStatus = 400
	c := f.connector()
	_, err := c.Issue(context.Background(), IssueRequest{CSRPEM: f.pki.csrPEM})
	if err == nil || !strings.Contains(err.Error(), "HTTP 400") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), sectigoTestSecret) {
		t.Fatal("password leaked into error")
	}
	if h := c.Health(context.Background()); strings.Contains(h.Detail, sectigoTestSecret) || h.Status != "degraded" {
		t.Fatalf("health = %+v", h)
	}
}

func TestSectigoGarbageCollectRefused(t *testing.T) {
	f := newSectigoFixture(t)
	f.collectBody = "not a certificate"
	if _, err := f.connector().Issue(context.Background(), IssueRequest{CSRPEM: f.pki.csrPEM}); err == nil {
		t.Fatal("non-PEM collect body must be refused")
	}
}

func TestSectigoRateLimit(t *testing.T) {
	f := newSectigoFixture(t)
	f.enrollStatus = 429
	_, err := f.connector().Issue(context.Background(), IssueRequest{CSRPEM: f.pki.csrPEM})
	var rl *RateLimitError
	if !errors.As(err, &rl) || rl.Reason != "upstream_429" || rl.RetryAfter != 7*time.Second || rl.ConnectorID != "sc-1" {
		t.Fatalf("err = %#v", err)
	}
}

func TestSectigoConfigRequired(t *testing.T) {
	f := newSectigoFixture(t)
	c := NewSectigoConnector("sc-1", SectigoConfig{BaseURL: f.srv.URL}, testClient("", "", ""))
	if _, err := c.Issue(context.Background(), IssueRequest{CSRPEM: f.pki.csrPEM}); err == nil {
		t.Fatal("missing org/profile/term must fail")
	}
	if _, err := f.connector().Issue(context.Background(), IssueRequest{CSRPEM: "junk"}); err == nil {
		t.Fatal("bad CSR must fail")
	}
}

func TestSectigoRevoke(t *testing.T) {
	f := newSectigoFixture(t)
	c := f.connector()
	if err := c.Revoke(context.Background(), RevokeRequest{SerialHex: "abcdef01", Reason: 1}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if f.revokePath != "/api/ssl/v2/revoke/4242" || f.revokeBody["reasonCode"] != "1" || f.revokeBody["reason"] == "" {
		t.Fatalf("revoke = %s %v", f.revokePath, f.revokeBody)
	}
	// 2 (CA compromise) is not offered by SCM: sent as unspecified.
	if err := c.Revoke(context.Background(), RevokeRequest{SerialHex: "0xABCDEF01", Reason: 2}); err != nil || f.revokeBody["reasonCode"] != "0" {
		t.Fatalf("unknown reason: err=%v body=%v", err, f.revokeBody)
	}
	// Serial derived from the leaf PEM when SerialHex is empty.
	if err := c.Revoke(context.Background(), RevokeRequest{CertificatePEM: pemOf(f.pki.leafDER)}); err != nil {
		t.Fatalf("revoke via PEM: %v", err)
	}
}

func TestSectigoRevokeRefusals(t *testing.T) {
	f := newSectigoFixture(t)
	c := f.connector()
	for name, list := range map[string]string{
		"none":       `[]`,
		"ambiguous":  `[{"sslId":1,"serialNumber":"ABCDEF01"},{"sslId":2,"serialNumber":"abcdef01"}]`,
		"other only": `[{"sslId":1,"serialNumber":"ABCDEF0102"}]`,
	} {
		f.listJSON, f.revokePath = list, ""
		if err := c.Revoke(context.Background(), RevokeRequest{SerialHex: "abcdef01"}); err == nil {
			t.Errorf("%s: want refusal", name)
		}
		if f.revokePath != "" {
			t.Errorf("%s: revoke must not be sent", name)
		}
	}
	if err := c.Revoke(context.Background(), RevokeRequest{}); err == nil {
		t.Error("no serial: want error")
	}
	f.listJSON, f.revokeStatus = `[{"sslId":4242,"serialNumber":"ABCDEF01"}]`, 400
	err := c.Revoke(context.Background(), RevokeRequest{SerialHex: "abcdef01"})
	if err == nil || strings.Contains(err.Error(), sectigoTestSecret) {
		t.Fatalf("revoke error = %v", err)
	}
}

func TestSectigoHealth(t *testing.T) {
	f := newSectigoFixture(t)
	c := f.connector()
	if h := c.Health(context.Background()); h.Status != "healthy" {
		t.Fatalf("health = %+v", h)
	}
	f.typesStatus = 401
	if h := c.Health(context.Background()); h.Status != "degraded" {
		t.Fatalf("health = %+v", h)
	}
	if c.ID() != "sc-1" || c.Type() != "sectigo" || c.Origin() != "synced" {
		t.Fatal("identity wrong")
	}
}

func TestSectigoCertificateLogin(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "kk-client"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	var gotPath string
	var gotPassword []string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "no cert", http.StatusUnauthorized)
			return
		}
		gotPath, gotPassword = r.URL.Path, r.Header.Values("password")
		_, _ = w.Write([]byte(`[]`))
	}))
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	srv.StartTLS()
	defer srv.Close()
	scCert, scKey, scCA := pemOf(der), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})), pemOf(srv.Certificate().Raw)
	c := NewSectigoConnector("sc-2", SectigoConfig{
		BaseURL: srv.URL, CustomerURI: "acme", Login: "svc",
		ClientCertPEM: scCert, ClientKeyPEM: scKey, CACertPEM: scCA,
	}, testClient(scCert, scKey, scCA))
	if h := c.Health(context.Background()); h.Status != "healthy" {
		t.Fatalf("health = %+v", h)
	}
	if gotPath != "/private/api/ssl/v2/types" || len(gotPassword) != 0 {
		t.Fatalf("cert login: path=%q password headers=%v", gotPath, gotPassword)
	}
	bad := NewSectigoConnector("sc-3", SectigoConfig{BaseURL: srv.URL, ClientCertPEM: "x", ClientKeyPEM: "y"}, testClient("", "", ""))
	h := bad.Health(context.Background())
	if h.Status != "degraded" || !strings.Contains(h.Detail, "invalid") {
		t.Fatalf("bad pem health = %+v", h)
	}
}
