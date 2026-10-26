// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package connectors

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const gcpTestPool = "/v1/projects/proj1/locations/us-central1/caPools/pool1"

type gcpCASFixture struct {
	srv  *httptest.Server
	saJS string

	mu         sync.Mutex
	tokenCalls int
	jwtOK      bool
	createQ    map[string][]string
	createBody map[string]any
	listFilter string
	revokeBody map[string]any
	revokePath string
	leafPEM    string
	listNames  []string
	// status forces every CAS (non-token) call to this code with errBody.
	status  int
	errBody string
	retry   string
}

func newGCPCASFixture(t *testing.T) *gcpCASFixture {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	pk8, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("pkcs8: %v", err)
	}
	f := &gcpCASFixture{}
	secretPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk8}))

	ekey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(0xabc123), Subject: pkix.Name{CommonName: "svc.example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ekey.PublicKey, ekey)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	f.leafPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.URL.Path == "/token" {
			f.tokenCalls++
			_ = r.ParseForm()
			parts := strings.Split(r.Form.Get("assertion"), ".")
			if r.Form.Get("grant_type") == "urn:ietf:params:oauth:grant-type:jwt-bearer" && len(parts) == 3 {
				sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
				d := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
				claims, _ := base64.RawURLEncoding.DecodeString(parts[1])
				var c map[string]any
				_ = json.Unmarshal(claims, &c)
				f.jwtOK = rsa.VerifyPKCS1v15(&rsaKey.PublicKey, crypto.SHA256, d[:], sig) == nil &&
					c["iss"] == "kk@proj1.iam.example" && c["scope"] == gcpCASScope && c["aud"] == f.srv.URL+"/token"
			}
			_, _ = io.WriteString(w, `{"access_token":"tok-1","expires_in":3600}`)
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok-1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if f.status != 0 {
			if f.retry != "" {
				w.Header().Set("Retry-After", f.retry)
			}
			w.WriteHeader(f.status)
			_, _ = io.WriteString(w, f.errBody)
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == gcpTestPool:
			_, _ = io.WriteString(w, `{"name":"pool1"}`)
		case r.Method == http.MethodPost && r.URL.Path == gcpTestPool+"/certificates":
			f.createQ = r.URL.Query()
			_ = json.NewDecoder(r.Body).Decode(&f.createBody)
			out, _ := json.Marshal(map[string]any{"name": "x", "pemCertificate": f.leafPEM,
				"pemCertificateChain": []string{f.leafPEM}})
			_, _ = w.Write(out)
		case r.Method == http.MethodGet && r.URL.Path == gcpTestPool+"/certificates":
			f.listFilter = r.URL.Query().Get("filter")
			var certs []map[string]string
			for _, n := range f.listNames {
				certs = append(certs, map[string]string{"name": n})
			}
			out, _ := json.Marshal(map[string]any{"certificates": certs})
			_, _ = w.Write(out)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, ":revoke"):
			f.revokePath = r.URL.Path
			_ = json.NewDecoder(r.Body).Decode(&f.revokeBody)
			_, _ = io.WriteString(w, `{}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(f.srv.Close)
	js, _ := json.Marshal(map[string]string{"client_email": "kk@proj1.iam.example", "private_key": secretPEM,
		"token_uri": "https://ignored.invalid/token"})
	f.saJS = string(js)
	return f
}

func (f *gcpCASFixture) conn(cfg GCPCASConfig) *GCPCASConnector {
	cfg.Project, cfg.Location, cfg.CAPool = "proj1", "us-central1", "pool1"
	cfg.BaseURL = f.srv.URL
	cfg.TokenURL = f.srv.URL + "/token"
	cfg.ServiceAccountJSON = f.saJS
	return NewGCPCASConnector("cas-1", cfg, f.srv.Client())
}

func TestGCPCASIssueSuccess(t *testing.T) {
	f := newGCPCASFixture(t)
	c := f.conn(GCPCASConfig{CertificateAuthorityID: "ca-1", CertificateTemplate: "projects/p/locations/l/certificateTemplates/t"})
	csr := testCSRPEM(t, "svc.example.com")
	res, err := c.Issue(context.Background(), IssueRequest{CSRPEM: csr})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if !f.jwtOK {
		t.Fatal("JWT bearer assertion not signed/claimed as expected")
	}
	if !strings.HasPrefix(f.createQ["certificateId"][0], "kk-") || len(f.createQ["certificateId"][0]) > 63 {
		t.Fatalf("certificateId = %v", f.createQ["certificateId"])
	}
	if f.createQ["issuingCertificateAuthorityId"][0] != "ca-1" || f.createQ["requestId"][0] == "" {
		t.Fatalf("query = %v", f.createQ)
	}
	if f.createBody["pemCsr"] != csr || f.createBody["lifetime"] != "7776000s" ||
		f.createBody["certificateTemplate"] != "projects/p/locations/l/certificateTemplates/t" {
		t.Fatalf("body = %v", f.createBody)
	}
	if strings.Count(res.CertificatePEM, "BEGIN CERTIFICATE") != 2 || res.FingerprintSHA256 == "" {
		t.Fatalf("result = %+v", res)
	}
}

func TestGCPCASTokenCachedAcrossCalls(t *testing.T) {
	f := newGCPCASFixture(t)
	c := f.conn(GCPCASConfig{})
	for i := 0; i < 2; i++ {
		if h := c.Health(context.Background()); h.Status != "healthy" {
			t.Fatalf("health = %+v", h)
		}
	}
	if f.tokenCalls != 1 {
		t.Fatalf("token calls = %d, want 1", f.tokenCalls)
	}
}

func TestGCPCASAmbientAuth(t *testing.T) {
	f := newGCPCASFixture(t)
	var flavor string
	meta := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flavor = r.Header.Get("Metadata-Flavor")
		_, _ = io.WriteString(w, `{"access_token":"tok-1","expires_in":3600}`)
	}))
	defer meta.Close()
	c := f.conn(GCPCASConfig{Auth: "ambient", MetadataURL: meta.URL, MetadataClient: meta.Client(), ServiceAccountJSON: ""})
	c.cfg.ServiceAccountJSON = ""
	if h := c.Health(context.Background()); h.Status != "healthy" {
		t.Fatalf("health = %+v", h)
	}
	if flavor != "Google" || f.tokenCalls != 0 {
		t.Fatalf("flavor=%q tokenCalls=%d", flavor, f.tokenCalls)
	}
}

// Ambient auth never falls back to the egress-guarded client: it would be
// refused by design, and silently using it for the metadata host is the bug
// MetadataClient exists to prevent.
func TestGCPCASAmbientAuthNeedsMetadataClient(t *testing.T) {
	f := newGCPCASFixture(t)
	c := f.conn(GCPCASConfig{Auth: "ambient"})
	if h := c.Health(context.Background()); h.Status == "healthy" || !strings.Contains(h.Detail, "metadata client") {
		t.Fatalf("health = %+v", h)
	}
}

func TestGCPCASClientErrorHidesSecret(t *testing.T) {
	f := newGCPCASFixture(t)
	f.status, f.errBody = http.StatusForbidden, `{"error":{"status":"PERMISSION_DENIED","message":"denied"}}`
	c := f.conn(GCPCASConfig{})
	_, err := c.Issue(context.Background(), IssueRequest{CSRPEM: testCSRPEM(t, "a.example.com")})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
	for _, s := range []string{"PRIVATE KEY", "tok-1", "BEGIN"} {
		if strings.Contains(err.Error(), s) {
			t.Fatalf("error leaks %q: %v", s, err)
		}
	}
	if h := c.Health(context.Background()); h.Status != "degraded" {
		t.Fatalf("health = %+v", h)
	}
}

func TestGCPCASBadServiceAccountJSONHidesSecret(t *testing.T) {
	f := newGCPCASFixture(t)
	c := f.conn(GCPCASConfig{ServiceAccountJSON: "not-json-SECRETFRAGMENT"})
	c.cfg.ServiceAccountJSON = "not-json-SECRETFRAGMENT"
	_, err := c.Issue(context.Background(), IssueRequest{CSRPEM: testCSRPEM(t, "a.example.com")})
	if err == nil || strings.Contains(err.Error(), "SECRETFRAGMENT") {
		t.Fatalf("err = %v", err)
	}
}

func TestGCPCASRateLimit(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"http429", http.StatusTooManyRequests, `{}`},
		{"resource_exhausted_json", http.StatusServiceUnavailable, `{"error":{"code":429,"status":"RESOURCE_EXHAUSTED"}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newGCPCASFixture(t)
			f.status, f.errBody, f.retry = tc.status, tc.body, "7"
			_, err := f.conn(GCPCASConfig{}).Issue(context.Background(), IssueRequest{CSRPEM: testCSRPEM(t, "a.example.com")})
			var rl *RateLimitError
			if !errors.As(err, &rl) || rl.RetryAfter != 7*time.Second || rl.ConnectorID != "cas-1" {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestGCPCASRefusesNonCertificateResponse(t *testing.T) {
	f := newGCPCASFixture(t)
	f.leafPEM = "garbage"
	if _, err := f.conn(GCPCASConfig{}).Issue(context.Background(), IssueRequest{CSRPEM: testCSRPEM(t, "a.example.com")}); err == nil {
		t.Fatal("expected error for unparseable pemCertificate")
	}
}

func TestGCPCASRevokeSuccess(t *testing.T) {
	f := newGCPCASFixture(t)
	name := "projects/proj1/locations/us-central1/caPools/pool1/certificates/kk-abc-1"
	f.listNames = []string{name}
	err := f.conn(GCPCASConfig{}).Revoke(context.Background(), RevokeRequest{SerialHex: "00ABC123", Reason: 1})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if f.listFilter != "certificate_description.subject_description.hex_serial_number=abc123" {
		t.Fatalf("filter = %q", f.listFilter)
	}
	if f.revokePath != "/v1/"+name+":revoke" || f.revokeBody["reason"] != "KEY_COMPROMISE" || f.revokeBody["requestId"] == "" {
		t.Fatalf("revoke path=%q body=%v", f.revokePath, f.revokeBody)
	}
}

func TestGCPCASRevokeSerialFromPEM(t *testing.T) {
	f := newGCPCASFixture(t)
	f.listNames = []string{"projects/proj1/locations/us-central1/caPools/pool1/certificates/c1"}
	if err := f.conn(GCPCASConfig{}).Revoke(context.Background(), RevokeRequest{CertificatePEM: f.leafPEM}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if !strings.HasSuffix(f.listFilter, "=abc123") || f.revokeBody["reason"] != "REVOCATION_REASON_UNSPECIFIED" {
		t.Fatalf("filter=%q body=%v", f.listFilter, f.revokeBody)
	}
}

func TestGCPCASRevokeRefusesAmbiguousOrMissing(t *testing.T) {
	pool := "projects/proj1/locations/us-central1/caPools/pool1/certificates/"
	for name, names := range map[string][]string{
		"zero": nil, "two": {pool + "a", pool + "b"},
		"foreign":   {"projects/other/locations/x/caPools/y/certificates/z"},
		"traversal": {pool + "a/../../b"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newGCPCASFixture(t)
			f.listNames = names
			if err := f.conn(GCPCASConfig{}).Revoke(context.Background(), RevokeRequest{SerialHex: "01"}); err == nil {
				t.Fatal("expected refusal")
			}
			if f.revokePath != "" {
				t.Fatalf("revoke must not be called, got %q", f.revokePath)
			}
		})
	}
}

func TestGCPCASRevokeRejectsNonHexSerial(t *testing.T) {
	f := newGCPCASFixture(t)
	if err := f.conn(GCPCASConfig{}).Revoke(context.Background(), RevokeRequest{SerialHex: `1" OR x`}); err == nil {
		t.Fatal("expected error")
	}
}

func TestGCPCASRevokeError(t *testing.T) {
	f := newGCPCASFixture(t)
	f.status, f.errBody = http.StatusNotFound, `{"error":{"status":"NOT_FOUND"}}`
	if err := f.conn(GCPCASConfig{}).Revoke(context.Background(), RevokeRequest{SerialHex: "01"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestGCPCASReasonMapping(t *testing.T) {
	want := map[int]string{0: "REVOCATION_REASON_UNSPECIFIED", 1: "KEY_COMPROMISE", 2: "CERTIFICATE_AUTHORITY_COMPROMISE",
		3: "AFFILIATION_CHANGED", 4: "SUPERSEDED", 5: "CESSATION_OF_OPERATION", 6: "CERTIFICATE_HOLD",
		8: "REVOCATION_REASON_UNSPECIFIED", 9: "PRIVILEGE_WITHDRAWN", 10: "ATTRIBUTE_AUTHORITY_COMPROMISE", 99: "REVOCATION_REASON_UNSPECIFIED"}
	for code, w := range want {
		if got := gcpRevocationReason(code); got != w {
			t.Errorf("reason %d = %s, want %s", code, got, w)
		}
	}
}

func TestGCPCASDefaultsAndIdentity(t *testing.T) {
	c := NewGCPCASConnector("x", GCPCASConfig{}, nil)
	if c.cfg.BaseURL != "https://privateca.googleapis.com" || c.cfg.LifetimeDays != 90 ||
		c.Type() != "gcp_cas" || c.Origin() != "synced" || c.ID() != "x" {
		t.Fatalf("defaults: %+v", c.cfg)
	}
}
