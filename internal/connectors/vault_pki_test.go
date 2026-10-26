// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package connectors

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// W36-04: request shapes pinned against the Vault PKI API docs
// (https://developer.hashicorp.com/vault/api-docs/secret/pki).

const vaultTestSecret = "s.TOPSECRETTOKEN"

func vaultTestCert(t *testing.T, cn string) (der []byte, certPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x39dd2e),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func vaultTestCSR(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("spiffe://example.test/svc")
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: "app.example.test"},
		DNSNames:       []string{"app.example.test", "alt.example.test"},
		EmailAddresses: []string{"ops@example.test"},
		IPAddresses:    []net.IP{net.ParseIP("10.0.0.7")},
		URIs:           []*url.URL{u},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

type vaultFake struct {
	mu       sync.Mutex
	srv      *httptest.Server
	leaf     string
	ca       string
	calls    []string
	headers  map[string][]http.Header
	bodies   map[string]map[string]any
	healthSC int
	signSC   int
	revokeSC int
	retry    string
	revoked  map[string]bool
}

func newVaultFake(t *testing.T) *vaultFake {
	t.Helper()
	_, leaf := vaultTestCert(t, "app.example.test")
	_, ca := vaultTestCert(t, "Vault Test CA")
	f := &vaultFake{leaf: leaf, ca: ca, healthSC: 200, signSC: 200, revokeSC: 200,
		headers: map[string][]http.Header{}, bodies: map[string]map[string]any{}, revoked: map[string]bool{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *vaultFake) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := r.Method + " " + r.URL.Path
	f.calls = append(f.calls, key)
	f.headers[key] = append(f.headers[key], r.Header.Clone())
	raw, _ := io.ReadAll(r.Body)
	if len(raw) > 0 {
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		f.bodies[key] = m
	}
	switch key {
	case "GET /v1/sys/health":
		w.WriteHeader(f.healthSC)
		_, _ = w.Write([]byte(`{"sealed":false}`))
	case "POST /v1/auth/approle/login", "POST /v1/auth/ar2/login":
		_, _ = w.Write([]byte(`{"auth":{"client_token":"` + vaultTestSecret + `"}}`))
	case "POST /v1/pki/sign/web", "POST /v1/pki2/sign/web":
		if f.signSC == 429 {
			w.Header().Set("Retry-After", f.retry)
		}
		if f.signSC != 200 {
			w.WriteHeader(f.signSC)
			_, _ = w.Write([]byte(`{"errors":["common name not allowed by this role"]}`))
			return
		}
		b, _ := json.Marshal(map[string]any{"data": map[string]any{
			"certificate": f.leaf, "issuing_ca": f.ca, "ca_chain": []string{f.ca},
			"serial_number": "39:dd:2e"}})
		_, _ = w.Write(b)
	case "POST /v1/pki/revoke":
		if f.revokeSC != 200 {
			w.WriteHeader(f.revokeSC)
			_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":{"revocation_time":1433269787}}`))
	case "LIST /v1/pki/certs":
		_, _ = w.Write([]byte(`{"data":{"keys":["39:dd:2e","0a:01"]}}`))
	case "GET /v1/pki/cert/39:dd:2e":
		b, _ := json.Marshal(map[string]any{"data": map[string]any{"certificate": f.leaf, "revocation_time": 0}})
		_, _ = w.Write(b)
	case "GET /v1/pki/cert/0a:01":
		b, _ := json.Marshal(map[string]any{"data": map[string]any{"certificate": f.ca, "revocation_time": 1667400107}})
		_, _ = w.Write(b)
	default:
		w.WriteHeader(404)
	}
}

func newVaultTestConnector(t *testing.T, f *vaultFake, cfg VaultPKIConfig) *VaultPKIConnector {
	t.Helper()
	cfg.BaseURL = f.srv.URL
	c, err := NewVaultPKIConnector("v1", cfg, f.srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestVaultPKIIssueTokenShapesAndBundle(t *testing.T) {
	f := newVaultFake(t)
	c := newVaultTestConnector(t, f, VaultPKIConfig{Token: vaultTestSecret, Role: "web", TTL: "72h", Namespace: "team-a"})
	res, err := c.Issue(context.Background(), IssueRequest{CSRPEM: vaultTestCSR(t)})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	key := "POST /v1/pki/sign/web"
	h := f.headers[key][0]
	if h.Get("X-Vault-Token") != vaultTestSecret || h.Get("X-Vault-Namespace") != "team-a" {
		t.Fatalf("headers: %v", h)
	}
	b := f.bodies[key]
	for field, want := range map[string]string{
		"common_name": "app.example.test",
		"alt_names":   "app.example.test,alt.example.test,ops@example.test",
		"ip_sans":     "10.0.0.7",
		"uri_sans":    "spiffe://example.test/svc",
		"ttl":         "72h",
		"format":      "pem",
	} {
		if b[field] != want {
			t.Errorf("%s = %v, want %q", field, b[field], want)
		}
	}
	if s, _ := b["csr"].(string); !strings.Contains(s, "BEGIN CERTIFICATE REQUEST") {
		t.Errorf("csr param missing")
	}
	blocks := 0
	rest := []byte(res.CertificatePEM)
	var first *pem.Block
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blocks == 0 {
			first = blk
		}
		blocks++
	}
	if blocks != 2 {
		t.Fatalf("bundle should be leaf+ca, got %d certs", blocks)
	}
	sum := sha256.Sum256(first.Bytes)
	if res.FingerprintSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("fingerprint must be of the leaf (first) cert")
	}
	if !strings.HasPrefix(res.CertificatePEM, strings.TrimSpace(f.leaf)) {
		t.Fatal("leaf must come first")
	}
	if c.Type() != "vault_pki" || c.Origin() != "synced" {
		t.Fatal("type/origin")
	}
}

func TestVaultPKIAppRoleLoginPerCall(t *testing.T) {
	f := newVaultFake(t)
	c := newVaultTestConnector(t, f, VaultPKIConfig{RoleID: "rid", SecretID: "sid", Role: "web"})
	if _, err := c.Issue(context.Background(), IssueRequest{CSRPEM: vaultTestCSR(t)}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Issue(context.Background(), IssueRequest{CSRPEM: vaultTestCSR(t)}); err != nil {
		t.Fatal(err)
	}
	login := "POST /v1/auth/approle/login"
	if len(f.headers[login]) != 2 {
		t.Fatalf("login must run per call, ran %d", len(f.headers[login]))
	}
	if f.headers[login][0].Get("X-Vault-Token") != "" {
		t.Fatal("login must not send a token")
	}
	if f.bodies[login]["role_id"] != "rid" || f.bodies[login]["secret_id"] != "sid" {
		t.Fatalf("login body: %v", f.bodies[login])
	}
	if f.headers["POST /v1/pki/sign/web"][0].Get("X-Vault-Token") != vaultTestSecret {
		t.Fatal("sign must use the login client_token")
	}
}

func TestVaultPKICustomMounts(t *testing.T) {
	f := newVaultFake(t)
	c := newVaultTestConnector(t, f, VaultPKIConfig{RoleID: "r", SecretID: "s", Role: "web", Mount: "/pki2/", AppRoleMount: "ar2"})
	if _, err := c.Issue(context.Background(), IssueRequest{CSRPEM: vaultTestCSR(t)}); err != nil {
		t.Fatal(err)
	}
	if len(f.headers["POST /v1/auth/ar2/login"]) != 1 || len(f.headers["POST /v1/pki2/sign/web"]) != 1 {
		t.Fatalf("calls: %v", f.calls)
	}
}

func TestVaultPKIIssueErrorsHideSecret(t *testing.T) {
	f := newVaultFake(t)
	f.signSC = 400
	c := newVaultTestConnector(t, f, VaultPKIConfig{Token: vaultTestSecret, Role: "web"})
	_, err := c.Issue(context.Background(), IssueRequest{CSRPEM: vaultTestCSR(t)})
	if err == nil || !strings.Contains(err.Error(), "HTTP 400") || !strings.Contains(err.Error(), "common name not allowed") {
		t.Fatalf("want vault 400 text, got %v", err)
	}
	if strings.Contains(err.Error(), vaultTestSecret) {
		t.Fatal("secret leaked into error")
	}
	if h := c.Health(context.Background()); h.Status != "degraded" || strings.Contains(h.Detail, vaultTestSecret) {
		t.Fatalf("health must carry last error without secret: %+v", h)
	}
}

func TestVaultPKIRateLimit(t *testing.T) {
	f := newVaultFake(t)
	f.signSC, f.retry = 429, "7"
	c := newVaultTestConnector(t, f, VaultPKIConfig{Token: vaultTestSecret, Role: "web"})
	_, err := c.Issue(context.Background(), IssueRequest{CSRPEM: vaultTestCSR(t)})
	var rl *RateLimitError
	if !errors.As(err, &rl) || rl.Reason != "upstream_429" || rl.RetryAfter != 7*time.Second || rl.ConnectorID != "v1" {
		t.Fatalf("want RateLimitError, got %#v", err)
	}
}

func TestVaultPKIRejectsNonCertificateResponse(t *testing.T) {
	f := newVaultFake(t)
	f.leaf = "not a certificate"
	c := newVaultTestConnector(t, f, VaultPKIConfig{Token: vaultTestSecret, Role: "web"})
	if _, err := c.Issue(context.Background(), IssueRequest{CSRPEM: vaultTestCSR(t)}); err == nil {
		t.Fatal("garbage certificate must be refused")
	}
}

func TestVaultPKIIssueNeedsRoleAndCSR(t *testing.T) {
	f := newVaultFake(t)
	c := newVaultTestConnector(t, f, VaultPKIConfig{Token: "t"})
	if _, err := c.Issue(context.Background(), IssueRequest{CSRPEM: vaultTestCSR(t)}); err == nil {
		t.Fatal("missing role must error")
	}
	c = newVaultTestConnector(t, f, VaultPKIConfig{Token: "t", Role: "web"})
	if _, err := c.Issue(context.Background(), IssueRequest{CSRPEM: "junk"}); err == nil {
		t.Fatal("bad CSR must error")
	}
}

func TestVaultPKIRevokeSerialFormat(t *testing.T) {
	f := newVaultFake(t)
	c := newVaultTestConnector(t, f, VaultPKIConfig{Token: vaultTestSecret, Role: "web"})
	if err := c.Revoke(context.Background(), RevokeRequest{SerialHex: "39dd2e", Reason: 1}); err != nil {
		t.Fatal(err)
	}
	key := "POST /v1/pki/revoke"
	if f.bodies[key]["serial_number"] != "39:dd:2e" || len(f.bodies[key]) != 1 {
		t.Fatalf("revoke body: %v", f.bodies[key])
	}
	if f.headers[key][0].Get("X-Vault-Token") != vaultTestSecret {
		t.Fatal("token header")
	}
	if err := c.Revoke(context.Background(), RevokeRequest{SerialHex: "zz"}); err == nil {
		t.Fatal("non-hex serial must be refused before any call")
	}
}

func TestVaultPKIRevokeError(t *testing.T) {
	f := newVaultFake(t)
	f.revokeSC = 403
	c := newVaultTestConnector(t, f, VaultPKIConfig{Token: vaultTestSecret})
	err := c.Revoke(context.Background(), RevokeRequest{SerialHex: "01"})
	if err == nil || !strings.Contains(err.Error(), "HTTP 403") || strings.Contains(err.Error(), vaultTestSecret) {
		t.Fatalf("revoke error: %v", err)
	}
}

func TestVaultSerialFromHex(t *testing.T) {
	for in, want := range map[string]string{"39DD2E": "39:dd:2e", "abc": "0a:bc", "39:dd": "39:dd", "01": "01"} {
		got, err := VaultSerialFromHex(in)
		if err != nil || got != want {
			t.Errorf("%q -> %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := VaultSerialFromHex(""); err == nil {
		t.Error("empty must error")
	}
}

func TestVaultPKIHealthStatuses(t *testing.T) {
	cases := map[int]string{200: "healthy", 429: "healthy", 472: "degraded", 473: "degraded",
		474: "degraded", 501: "degraded", 503: "degraded", 530: "degraded", 500: "degraded"}
	for code, want := range cases {
		f := newVaultFake(t)
		f.healthSC = code
		c := newVaultTestConnector(t, f, VaultPKIConfig{Token: "t"})
		h := c.Health(context.Background())
		if h.Status != want {
			t.Errorf("HTTP %d: status %q want %q (%s)", code, h.Status, want, h.Detail)
		}
		if f.headers["GET /v1/sys/health"][0].Get("X-Vault-Token") != "" {
			t.Error("health must be unauthenticated")
		}
	}
	f := newVaultFake(t)
	c := newVaultTestConnector(t, f, VaultPKIConfig{Token: "t"})
	f.srv.Close()
	if h := c.Health(context.Background()); h.Status != "degraded" {
		t.Errorf("unreachable: %+v", h)
	}
}

func TestVaultPKIListCertificates(t *testing.T) {
	f := newVaultFake(t)
	c := newVaultTestConnector(t, f, VaultPKIConfig{Token: vaultTestSecret})
	recs, err := c.ListCertificates(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 || recs[0].Revoked || !recs[1].Revoked || recs[1].Serial != "0a:01" {
		t.Fatalf("records: %+v", recs)
	}
	if f.headers["LIST /v1/pki/certs"][0].Get("X-Vault-Token") != vaultTestSecret {
		t.Fatal("list is authenticated")
	}
}

func TestNewVaultPKIConnectorValidation(t *testing.T) {
	if _, err := NewVaultPKIConnector("x", VaultPKIConfig{Token: "t"}, nil); err == nil {
		t.Error("base url required")
	}
	if _, err := NewVaultPKIConnector("x", VaultPKIConfig{BaseURL: "https://v"}, nil); err == nil {
		t.Error("credentials required")
	}
	if _, err := NewVaultPKIConnector("x", VaultPKIConfig{BaseURL: "https://v", Token: "t", CACertPEM: "junk"}, nil); err == nil {
		t.Error("bad CA pem must error")
	}
}

func TestVaultPKIPrivateCATrust(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	t.Cleanup(srv.Close)
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	c, err := NewVaultPKIConnector("v", VaultPKIConfig{BaseURL: srv.URL, Token: "t", CACertPEM: caPEM},
		testClient("", "", caPEM))
	if err != nil {
		t.Fatal(err)
	}
	if h := c.Health(context.Background()); h.Status != "healthy" {
		t.Fatalf("pinned CA should verify: %+v", h)
	}
	// Without the pin the self-signed server must be refused.
	c2, _ := NewVaultPKIConnector("v", VaultPKIConfig{BaseURL: srv.URL, Token: "t"}, testClient("", "", ""))
	if h := c2.Health(context.Background()); h.Status != "degraded" {
		t.Fatalf("untrusted CA must fail: %+v", h)
	}
}
