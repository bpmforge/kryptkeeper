// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/connectors"
	"kryptkeeper/internal/est"
	"kryptkeeper/internal/keystore"
	"kryptkeeper/internal/wstep"
)

// W27-35: the digicert/scep/est/wstep connector types through the hub API.

type upstreamTestCreds struct {
	OutboundCredentialStore
	payloads map[string]string
	meta     map[string]OutboundCredentialMeta
}

// Get answers metadata for every known payload: api_token, tenant default,
// unless meta overrides it.
func (s *upstreamTestCreds) Get(_ context.Context, id string) (OutboundCredentialMeta, error) {
	if m, ok := s.meta[id]; ok {
		return m, nil
	}
	if _, ok := s.payloads[id]; !ok {
		return OutboundCredentialMeta{}, errOutboundCredentialNotFound
	}
	return OutboundCredentialMeta{ID: id, CredentialType: CredentialTypeAPIToken, Tenant: DefaultTenant}, nil
}

func (s *upstreamTestCreds) Resolve(_ context.Context, id string) ([]byte, error) {
	p, ok := s.payloads[id]
	if !ok {
		return nil, errOutboundCredentialNotFound
	}
	return []byte(p), nil
}

type upstreamRecordingAudit struct {
	mu      sync.Mutex
	entries []AuditEntry
}

func (a *upstreamRecordingAudit) ListEntries(context.Context, AuditListQuery) (AuditListResult, error) {
	return AuditListResult{}, nil
}
func (a *upstreamRecordingAudit) AppendEntry(_ context.Context, e AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, e)
	return nil
}

func newUpstreamTestMux(t *testing.T, creds OutboundCredentialStore) (*http.ServeMux, ConnectorStore, *upstreamRecordingAudit) {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	prev := egressAllowLoopback
	prevPlain := upstreamAllowPlainHTTP
	egressAllowLoopback, upstreamAllowPlainHTTP = true, true
	t.Cleanup(func() { egressAllowLoopback, upstreamAllowPlainHTTP = prev, prevPlain })
	store := newConnectorTestStore(t)
	audit := &upstreamRecordingAudit{}
	mux := http.NewServeMux()
	RegisterConnectorHandlers(mux, NewAuthenticatorFromEnv(), store, nil, creds, audit)
	return mux, store, audit
}

func upstreamCSR(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func createUpstream(t *testing.T, mux *http.ServeMux, typ, cfg, credRef string) string {
	t.Helper()
	rec := doJSON(t, mux, http.MethodPost, "/api/v1/connectors", map[string]string{
		"name": typ + "-up", "type": typ, "config_json": cfg, "credential_ref": credRef,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create %s: %d %s", typ, rec.Code, rec.Body.String())
	}
	var resp struct {
		Data ConnectorRecord `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp.Data.ID
}

func fingerprintOfPEM(t *testing.T, certPEM string) string {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatal("result is not PEM")
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:])
}

func TestUpstreamDigiCertCreateAndIssue(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "up.example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	leaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	wantFP := sha256.Sum256(der)

	var rateLimit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-DC-DEVKEY") != "dc-secret-key" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if rateLimit {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		switch {
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/services/v2/order/certificate/"):
			_, _ = io.ReadAll(r.Body)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 1, "certificate": map[string]any{"id": 2}})
		case strings.HasSuffix(r.URL.Path, "/download/format/pem_all"):
			_, _ = w.Write(leaf)
		case r.URL.Path == "/services/v2/user/me":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	creds := &upstreamTestCreds{payloads: map[string]string{"cred-dc": `{"api_key":"dc-secret-key"}`}}
	mux, store, _ := newUpstreamTestMux(t, creds)
	id := createUpstream(t, mux, "digicert", `{"base_url":"`+srv.URL+`","organization_id":99}`, "cred-dc")

	registry, err := BuildConnectorRegistry(context.Background(), store, nil, creds)
	if err != nil {
		t.Fatal(err)
	}
	res, err := registry.Issue(context.Background(), id, connectors.IssueRequest{CSRPEM: upstreamCSR(t, "up.example.com")})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if res.FingerprintSHA256 != hex.EncodeToString(wantFP[:]) {
		t.Fatalf("fingerprint %q", res.FingerprintSHA256)
	}

	// 429 surfaces unchanged and degrades Health (the adapter remembers it).
	rateLimit = true
	conn, _ := registry.Get(id)
	_, err = conn.Issue(context.Background(), connectors.IssueRequest{CSRPEM: upstreamCSR(t, "up.example.com")})
	if err == nil || !strings.Contains(err.Error(), "rate limited (HTTP 429)") {
		t.Fatalf("429 must surface unchanged: %v", err)
	}
	if h := conn.Health(context.Background()); h.Status != "degraded" || !strings.Contains(h.Detail, "rate limited") {
		t.Fatalf("health after throttle: %+v", h)
	}
	if strings.Contains(err.Error(), "dc-secret-key") {
		t.Fatal("secret leaked into error")
	}
}

func TestUpstreamWSTEPCreateAndIssue(t *testing.T) {
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("test-upstream-wstep-passphrase!!"))
	if err != nil {
		t.Fatal(err)
	}
	engine := ca.NewEngine(keys, ca.NewMemStore())
	root, err := engine.CreateRootCA("Up Root", pkix.Name{CommonName: "Up Root"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	inner := wstep.NewServer(engine, root.ID).WithAuthenticator(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(wstep.WithIdentity(r.Context(), wstep.Identity{
				Method: "kerberos", Principal: "svc@CORP.EXAMPLE", Subject: pkix.Name{CommonName: "app.corp.example"},
			})))
		})
	}).Handler()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "svc-enroll" || p != "ws-pass-1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		inner.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	creds := &upstreamTestCreds{payloads: map[string]string{"cred-ws": `{"password":"ws-pass-1"}`}}
	mux, store, _ := newUpstreamTestMux(t, creds)
	id := createUpstream(t, mux, "wstep", `{"endpoint_url":"`+srv.URL+`","username":"svc-enroll","template_name":"WebServer"}`, "cred-ws")
	registry, _ := BuildConnectorRegistry(context.Background(), store, nil, creds)
	res, err := registry.Issue(context.Background(), id, connectors.IssueRequest{CSRPEM: upstreamCSR(t, "app.corp.example")})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if res.FingerprintSHA256 != fingerprintOfPEM(t, res.CertificatePEM) {
		t.Fatalf("fingerprint mismatch: %q", res.FingerprintSHA256)
	}
}

func TestUpstreamESTCreateAndIssue(t *testing.T) {
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("test-upstream-est-passphrase!!!!"))
	if err != nil {
		t.Fatal(err)
	}
	engine := ca.NewEngine(keys, ca.NewMemStore())
	root, err := engine.CreateRootCA("Up EST Root", pkix.Name{CommonName: "Up EST Root"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte("est-pass-1"), bcrypt.MinCost)
	estSrv := est.NewServer(engine, root.ID)
	if err := estSrv.WithBasicUsers([]est.User{{Username: "est-user", BcryptHash: string(hash), AllowedDNSSuffixes: []string{".example.com"}}}); err != nil {
		t.Fatal(err)
	}
	// The EST server refuses plaintext. The egress client cannot be pointed
	// at a self-signed httptest TLS cert without loosening verification, so
	// the fixture marks the request as TLS-terminated instead.
	estHandler := estSrv.Handler()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.TLS = &tls.ConnectionState{HandshakeComplete: true}
		estHandler.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	creds := &upstreamTestCreds{payloads: map[string]string{"cred-est": `{"password":"est-pass-1"}`}}
	mux, store, _ := newUpstreamTestMux(t, creds)
	id := createUpstream(t, mux, "est", `{"base_url":"`+srv.URL+`","username":"est-user"}`, "cred-est")
	registry, _ := BuildConnectorRegistry(context.Background(), store, nil, creds)
	res, err := registry.Issue(context.Background(), id, connectors.IssueRequest{CSRPEM: upstreamCSR(t, "legacy.example.com")})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if res.FingerprintSHA256 != fingerprintOfPEM(t, res.CertificatePEM) {
		t.Fatalf("fingerprint mismatch: %q", res.FingerprintSHA256)
	}
}

// SCEP issuance needs a signer and decrypter and is proven against the real
// internal/scep server in internal/connectors; here the hub wiring: the row
// is accepted without a credential, reaches the registry, and probes
// GetCACaps through the egress client.
func TestUpstreamSCEPCreateRegistersAndProbes(t *testing.T) {
	var sawCaps bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("operation") == "GetCACaps" {
			sawCaps = true
			_, _ = w.Write([]byte("POSTPKIOperation\nSHA-256\n"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	mux, store, _ := newUpstreamTestMux(t, nil)
	id := createUpstream(t, mux, "scep", `{"endpoint_url":"`+srv.URL+`"}`, "")
	registry, _ := BuildConnectorRegistry(context.Background(), store, nil, nil)
	conn, err := registry.Get(id)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	if h := conn.Health(context.Background()); h.Status != "healthy" || !sawCaps {
		t.Fatalf("scep health %+v caps=%v", h, sawCaps)
	}
}

func TestUpstreamCreateRefusals(t *testing.T) {
	creds := &upstreamTestCreds{payloads: map[string]string{}}
	mux, store, audit := newUpstreamTestMux(t, creds)
	const secret = "sup3r-s3cret-value"
	cases := []struct {
		name, typ, cfg, ref, want string
	}{
		{"forbidden key", "digicert", `{"organization_id":1,"api_key":"` + secret + `"}`, "c", "credential_ref"},
		{"nested forbidden key", "est", `{"base_url":"https://e.example.com","username":"u","x":{"Password":"` + secret + `"}}`, "c", "credential_ref"},
		{"missing org", "digicert", `{}`, "c", "organization_id"},
		{"missing endpoint", "scep", `{}`, "", "endpoint_url"},
		{"missing username", "est", `{"base_url":"https://e.example.com"}`, "c", "username"},
		{"missing template", "wstep", `{"endpoint_url":"https://w.example.com","username":"u"}`, "c", "template_name"},
		{"missing credential_ref", "wstep", `{"endpoint_url":"https://w.example.com","username":"u","template_name":"t"}`, "", "credential_ref"},
		{"bad type", "bogus", `{}`, "", "digicert|scep"},
	}
	for _, tc := range cases {
		before := len(audit.entries)
		rec := doJSON(t, mux, http.MethodPost, "/api/v1/connectors", map[string]string{
			"name": "x", "type": tc.typ, "config_json": tc.cfg, "credential_ref": tc.ref,
		})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: status %d %s", tc.name, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), tc.want) {
			t.Fatalf("%s: body %q lacks %q", tc.name, rec.Body.String(), tc.want)
		}
		if strings.Contains(rec.Body.String(), secret) {
			t.Fatalf("%s: secret echoed in response", tc.name)
		}
		if len(audit.entries) != before+1 {
			t.Fatalf("%s: want one audit row", tc.name)
		}
		last := audit.entries[len(audit.entries)-1]
		if last.Action != "connector.create" || last.Outcome != AuditOutcomeFailure {
			t.Fatalf("%s: audit %+v", tc.name, last)
		}
		raw, _ := json.Marshal(last)
		if strings.Contains(string(raw), secret) {
			t.Fatalf("%s: secret in audit row", tc.name)
		}
	}
	recs, _ := store.List(context.Background())
	if len(recs) != 0 {
		t.Fatalf("refused creates persisted %d rows", len(recs))
	}
}

func TestUpstreamHealthWithoutCredentialIsVisibleDegraded(t *testing.T) {
	conn := NewUpstreamIssuerConnector(ConnectorRecord{ID: "c1", Type: "est", ConfigJSON: `{"base_url":"https://e.example.com","username":"u"}`, CredentialRef: "gone"},
		&upstreamTestCreds{payloads: map[string]string{}})
	if h := conn.Health(context.Background()); h.Status != "degraded" || h.Detail == "" {
		t.Fatalf("health: %+v", h)
	}
}

// Credentialed upstream connectors must never send their secret over plain
// http; SCEP (no credential) may.
func TestUpstreamConnectorClientRequiresHTTPSWhenCredentialed(t *testing.T) {
	prev := egressAllowLoopback
	egressAllowLoopback = true
	t.Cleanup(func() { egressAllowLoopback = prev })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer srv.Close()

	if _, err := upstreamConnectorHTTPClient(time.Second, true).Get(srv.URL); err == nil || !strings.Contains(err.Error(), "https required") {
		t.Fatalf("credentialed client over http: err = %v, want https required", err)
	}
	resp, err := upstreamConnectorHTTPClient(time.Second, false).Get(srv.URL)
	if err != nil {
		t.Fatalf("scep client over http: %v", err)
	}
	resp.Body.Close()
}
