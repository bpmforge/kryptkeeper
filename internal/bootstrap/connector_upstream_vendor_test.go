// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"kryptkeeper/internal/connectors"
)

// W36-11: the seven vendor CA connector types through the hub.

func TestUpstreamVendorConfigValidation(t *testing.T) {
	const secret = "vendor-s3cret"
	good := map[string]string{
		"vault_pki":  `{"base_url":"https://vault.example:8200","role":"web"}`,
		"ejbca":      `{"base_url":"https://ejbca.example","certificate_profile_name":"p","end_entity_profile_name":"e","certificate_authority_name":"ca"}`,
		"aws_pca":    `{"certificate_authority_arn":"arn:aws:acm-pca:x","region":"us-east-1"}`,
		"gcp_cas":    `{"project":"p","location":"l","ca_pool":"c"}`,
		"sectigo":    `{"customer_uri":"acme","org_id":5,"cert_type":423,"term_days":365}`,
		"globalsign": `{}`,
		"entrust":    `{"requester_name":"n","requester_email":"e@example.com","requester_phone":"1"}`,
	}
	for typ, cfg := range good {
		if err := validateUpstreamConnector(ConnectorRecord{Type: typ, ConfigJSON: cfg, CredentialRef: "c"}); err != nil {
			t.Errorf("%s: valid config refused: %v", typ, err)
		}
	}
	bad := []struct{ name, typ, cfg, want string }{
		{"vault no base", "vault_pki", `{"role":"r"}`, "base_url"},
		{"vault no role", "vault_pki", `{"base_url":"https://v.example"}`, "role"},
		{"ejbca no profile", "ejbca", `{"base_url":"https://e.example","end_entity_profile_name":"e","certificate_authority_name":"c"}`, "certificate_profile_name"},
		{"ejbca no ca", "ejbca", `{"base_url":"https://e.example","certificate_profile_name":"p","end_entity_profile_name":"e"}`, "certificate_authority_name"},
		{"aws no arn", "aws_pca", `{"region":"r"}`, "certificate_authority_arn"},
		{"aws no region", "aws_pca", `{"certificate_authority_arn":"a"}`, "region"},
		{"aws bad auth", "aws_pca", `{"certificate_authority_arn":"a","region":"r","auth":"x"}`, "auth"},
		{"gcp no project", "gcp_cas", `{"location":"l","ca_pool":"c"}`, "project"},
		{"gcp no pool", "gcp_cas", `{"project":"p","location":"l"}`, "ca_pool"},
		{"sectigo no customer", "sectigo", `{"org_id":1,"cert_type":1,"term_days":1}`, "customer_uri"},
		{"sectigo no org", "sectigo", `{"customer_uri":"a","cert_type":1,"term_days":1}`, "org_id"},
		{"sectigo string cert type", "sectigo", `{"customer_uri":"a","org_id":1,"cert_type":"x","term_days":1}`, "cert_type"},
		{"sectigo no term", "sectigo", `{"customer_uri":"a","org_id":1,"cert_type":1}`, "term_days"},
		{"entrust no phone", "entrust", `{"requester_name":"n","requester_email":"e"}`, "requester_phone"},
		{"entrust numeric cert type", "entrust", `{"cert_type":5,"requester_name":"n","requester_email":"e","requester_phone":"p"}`, "cert_type"},
		{"bad ca pem", "globalsign", `{"ca_cert_pem":"nope"}`, "ca_cert_pem"},
		{"bad base url", "globalsign", `{"base_url":"ftp://x"}`, "base_url"},
	}
	for _, tc := range bad {
		err := validateUpstreamConnector(ConnectorRecord{Type: tc.typ, ConfigJSON: tc.cfg, CredentialRef: "c"})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want mention of %q", tc.name, err, tc.want)
		}
	}
	for _, key := range []string{"secret_id", "secret_access_key", "session_token", "service_account_json", "client_key_pem", "api_secret", "api_key", "token"} {
		cfg := fmt.Sprintf(`{"base_url":"https://v.example","role":"r","%s":%q}`, key, secret)
		err := validateUpstreamConnector(ConnectorRecord{Type: "vault_pki", ConfigJSON: cfg, CredentialRef: "c"})
		if err == nil || !strings.Contains(err.Error(), "credential_ref") || strings.Contains(err.Error(), secret) {
			t.Errorf("forbidden key %s: err = %v", key, err)
		}
	}
	if err := validateUpstreamConnector(ConnectorRecord{Type: "ejbca", ConfigJSON: good["ejbca"]}); !errors.Is(err, errUpstreamCredentialRequired) {
		t.Errorf("ejbca without credential_ref: %v", err)
	}
}

func TestUpstreamVendorCredentialPayloads(t *testing.T) {
	pair := upstreamCredentialPayload{ClientCertPEM: "c", ClientKeyPEM: "k"}
	cases := []struct {
		name, typ string
		cfg       upstreamConnectorConfig
		p         upstreamCredentialPayload
		missing   bool
	}{
		{"vault token", "vault_pki", upstreamConnectorConfig{}, upstreamCredentialPayload{Token: "t"}, false},
		{"vault approle", "vault_pki", upstreamConnectorConfig{}, upstreamCredentialPayload{RoleID: "r", SecretID: "s"}, false},
		{"vault half approle", "vault_pki", upstreamConnectorConfig{}, upstreamCredentialPayload{RoleID: "r"}, true},
		{"ejbca pair", "ejbca", upstreamConnectorConfig{}, pair, false},
		{"ejbca no key", "ejbca", upstreamConnectorConfig{}, upstreamCredentialPayload{ClientCertPEM: "c"}, true},
		{"aws static", "aws_pca", upstreamConnectorConfig{}, upstreamCredentialPayload{AccessKeyID: "a", SecretAccessKey: "s"}, false},
		{"aws static missing", "aws_pca", upstreamConnectorConfig{}, upstreamCredentialPayload{AccessKeyID: "a"}, true},
		{"aws ambient", "aws_pca", upstreamConnectorConfig{Auth: "ambient"}, upstreamCredentialPayload{}, false},
		{"gcp sa", "gcp_cas", upstreamConnectorConfig{}, upstreamCredentialPayload{ServiceAccountJSON: "{}"}, false},
		{"gcp sa missing", "gcp_cas", upstreamConnectorConfig{}, upstreamCredentialPayload{}, true},
		{"gcp ambient", "gcp_cas", upstreamConnectorConfig{Auth: "ambient"}, upstreamCredentialPayload{}, false},
		{"sectigo password", "sectigo", upstreamConnectorConfig{}, upstreamCredentialPayload{Login: "l", Password: "p"}, false},
		{"sectigo cert login", "sectigo", upstreamConnectorConfig{}, pair, false},
		{"sectigo neither", "sectigo", upstreamConnectorConfig{}, upstreamCredentialPayload{Login: "l"}, true},
		{"globalsign", "globalsign", upstreamConnectorConfig{}, upstreamCredentialPayload{APIKey: "k", APISecret: "s"}, false},
		{"globalsign no secret", "globalsign", upstreamConnectorConfig{}, upstreamCredentialPayload{APIKey: "k"}, true},
		{"entrust full", "entrust", upstreamConnectorConfig{}, upstreamCredentialPayload{Username: "u", APIKey: "k", ClientCertPEM: "c", ClientKeyPEM: "k"}, false},
		{"entrust no pair", "entrust", upstreamConnectorConfig{}, upstreamCredentialPayload{Username: "u", APIKey: "k"}, true},
		{"digicert", "digicert", upstreamConnectorConfig{}, upstreamCredentialPayload{APIKey: "k"}, false},
		{"est no password", "est", upstreamConnectorConfig{}, upstreamCredentialPayload{}, true},
	}
	for _, tc := range cases {
		if got := upstreamSecretMissing(tc.typ, tc.cfg, tc.p) != ""; got != tc.missing {
			t.Errorf("%s: missing = %v, want %v", tc.name, got, tc.missing)
		}
	}
	if upstreamNeedsCredential("scep", upstreamConnectorConfig{}) {
		t.Error("scep needs no credential")
	}
	if upstreamNeedsCredential("gcp_cas", upstreamConnectorConfig{Auth: "ambient"}) || upstreamNeedsCredential("aws_pca", upstreamConnectorConfig{Auth: "ambient"}) {
		t.Error("ambient aws_pca/gcp_cas need no credential")
	}
	if !upstreamNeedsCredential("aws_pca", upstreamConnectorConfig{}) || !upstreamNeedsCredential("vault_pki", upstreamConnectorConfig{Auth: "ambient"}) {
		t.Error("static aws_pca and other types still need a credential")
	}
}

func TestUpstreamAmbientCreateNeedsNoCredentialRef(t *testing.T) {
	mux, _, _ := newUpstreamTestMux(t, &upstreamTestCreds{payloads: map[string]string{}})
	createUpstream(t, mux, "gcp_cas", `{"project":"p","location":"l","ca_pool":"c","auth":"ambient"}`, "")
	createUpstream(t, mux, "aws_pca", `{"certificate_authority_arn":"a","region":"r","auth":"ambient"}`, "")
	rec := doJSON(t, mux, http.MethodPost, "/api/v1/connectors", map[string]string{
		"name": "x", "type": "gcp_cas", "config_json": `{"project":"p","location":"l","ca_pool":"c"}`,
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("static gcp_cas without credential_ref: %d", rec.Code)
	}
}

func TestGCPMetadataClientDialsOnlyTheFixedAddress(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer srv.Close()
	prev := gcpMetadataDialAddr
	gcpMetadataDialAddr = strings.TrimPrefix(srv.URL, "http://")
	t.Cleanup(func() { gcpMetadataDialAddr = prev })
	// The URL host is operator-looking, but the dialer ignores it.
	resp, err := gcpMetadataHTTPClient().Get("http://attacker.example:9999/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if hits != 1 {
		t.Fatalf("fixed address was not the one dialled (hits=%d)", hits)
	}
	if gcpMetadataAddr != "169.254.169.254:80" {
		t.Fatalf("production address changed: %s", gcpMetadataAddr)
	}
}

func vaultTestServer(t *testing.T, onRevoke func(serial string)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/sys/health":
			w.WriteHeader(http.StatusOK)
		case r.URL.Path == "/v1/pki/revoke" && r.Method == http.MethodPost:
			if r.Header.Get("X-Vault-Token") != "vault-token" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			onRevoke(body["serial_number"])
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestUpstreamAdapterRevokeDelegatesAndCanRevoke(t *testing.T) {
	var got string
	srv := vaultTestServer(t, func(s string) { got = s })
	creds := &upstreamTestCreds{payloads: map[string]string{"cv": `{"token":"vault-token"}`}}
	mux, store, _ := newUpstreamTestMux(t, creds)
	id := createUpstream(t, mux, "vault_pki", fmt.Sprintf(`{"base_url":%q,"role":"web"}`, srv.URL), "cv")
	rec, err := store.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	reg := connectors.NewRegistry()
	reg.Register(buildRuntimeConnector(rec, nil, creds))
	if !reg.SupportsRevoke(id) {
		t.Fatal("vault_pki must report revoke support")
	}
	if err := reg.Revoke(context.Background(), id, connectors.RevokeRequest{SerialHex: "0a:1b"}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if got == "" {
		t.Fatal("revoke did not reach the upstream")
	}
	// A bad token surfaces as an error, not a silent success.
	creds.payloads["cv"] = `{"token":"wrong"}`
	if err := reg.Revoke(context.Background(), id, connectors.RevokeRequest{SerialHex: "0a1b"}); err == nil {
		t.Fatal("upstream refusal must surface")
	}

	for typ, want := range map[string]bool{
		"digicert": true, "vault_pki": true, "ejbca": true, "aws_pca": true, "gcp_cas": true,
		"sectigo": true, "globalsign": true, "entrust": true, "scep": false, "est": false, "wstep": false,
	} {
		c := &upstreamConnector{connTyp: typ}
		if c.CanRevoke() != want {
			t.Errorf("CanRevoke(%s) = %v, want %v", typ, c.CanRevoke(), want)
		}
	}
	for _, typ := range []string{"scep", "est", "wstep"} {
		r2 := connectors.NewRegistry()
		r2.Register(NewUpstreamIssuerConnector(ConnectorRecord{ID: "x-" + typ, Type: typ, ConfigJSON: `{}`}, creds))
		if r2.SupportsRevoke("x-" + typ) {
			t.Errorf("%s must not report revoke support", typ)
		}
		if err := r2.Revoke(context.Background(), "x-"+typ, connectors.RevokeRequest{}); !errors.Is(err, connectors.ErrRevokeUnsupported) {
			t.Errorf("%s revoke err = %v", typ, err)
		}
	}
}

func TestConnectorTestRoute(t *testing.T) {
	srv := vaultTestServer(t, func(string) {})
	creds := &upstreamTestCreds{payloads: map[string]string{"cv": `{"token":"vault-token"}`}}
	mux, store, audit := newUpstreamTestMux(t, creds)
	healthy := createUpstream(t, mux, "vault_pki", fmt.Sprintf(`{"base_url":%q,"role":"web"}`, srv.URL), "cv")

	rec := doJSON(t, mux, http.MethodPost, "/api/v1/connectors/"+healthy+"/test", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("healthy: %d %s", rec.Code, rec.Body.String())
	}
	var out struct{ Status, Detail string }
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.Status != "healthy" {
		t.Fatalf("healthy body: %s", rec.Body.String())
	}
	if last := audit.entries[len(audit.entries)-1]; last.Action != "connector.test" || last.Outcome != AuditOutcomeSuccess {
		t.Fatalf("audit: %+v", last)
	}

	// Degraded: credential_ref that no longer resolves.
	if _, err := store.Create(context.Background(), ConnectorRecord{ID: "conn-deg", Name: "d", Type: "vault_pki",
		ConfigJSON: fmt.Sprintf(`{"base_url":%q,"role":"web"}`, srv.URL), CredentialRef: "gone"}); err != nil {
		t.Fatal(err)
	}
	rec = doJSON(t, mux, http.MethodPost, "/api/v1/connectors/conn-deg/test", nil)
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != http.StatusOK || out.Status != "degraded" || out.Detail == "" {
		t.Fatalf("degraded: %d %s", rec.Code, rec.Body.String())
	}

	if rec := doJSON(t, mux, http.MethodPost, "/api/v1/connectors/conn-nope/test", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown id: %d", rec.Code)
	}
	if rec := doJSON(t, mux, http.MethodGet, "/api/v1/connectors/"+healthy+"/test", nil); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d", rec.Code)
	}

	// Non-admin: the handler refuses before touching the store.
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/connectors/"+healthy+"/test", nil)
	handleConnectorTest(w, r, AuthPrincipal{ID: "u", Role: "viewer"}, healthy, store, nil, creds, audit)
	if w.Code != http.StatusForbidden {
		t.Fatalf("non-admin: %d", w.Code)
	}
	if last := audit.entries[len(audit.entries)-1]; last.Outcome != AuditOutcomeDenied {
		t.Fatalf("non-admin audit: %+v", last)
	}
}

// --- ACME revoke -----------------------------------------------------------

type fakeRevokeConnector struct {
	connectors.IssuerConnector
	mu      sync.Mutex
	revoked []connectors.RevokeRequest
}

func (f *fakeRevokeConnector) Revoke(_ context.Context, r connectors.RevokeRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked = append(f.revoked, r)
	return nil
}

type plainFakeConnector struct{ connectors.IssuerConnector }

func TestDCVWrapperForwardsRevoke(t *testing.T) {
	inner := &fakeRevokeConnector{}
	w := wrapWithDCVTracking(inner, "t", &DCVTracker{})
	rc, ok := w.(connectors.RevokingConnector)
	if !ok {
		t.Fatal("wrapper must implement RevokingConnector")
	}
	if err := rc.Revoke(context.Background(), connectors.RevokeRequest{SerialHex: "01"}); err != nil || len(inner.revoked) != 1 {
		t.Fatalf("forward: err=%v n=%d", err, len(inner.revoked))
	}
	if cr, ok := w.(connectors.RevokeCapable); !ok || !cr.CanRevoke() {
		t.Fatal("wrapper must report CanRevoke for a revoking inner")
	}
	plain := wrapWithDCVTracking(plainFakeConnector{}, "t", &DCVTracker{})
	if plain.(connectors.RevokeCapable).CanRevoke() {
		t.Fatal("wrapper over a non-revoking connector must not claim revoke")
	}
	if err := plain.(connectors.RevokingConnector).Revoke(context.Background(), connectors.RevokeRequest{}); !errors.Is(err, connectors.ErrRevokeUnsupported) {
		t.Fatalf("err = %v", err)
	}
}

func TestACMEConnectorRevokesWithStoredAccountKey(t *testing.T) {
	solverPort := freeLocalPort(t)
	var mu sync.Mutex
	var revokeStatus []int
	upstream := newTestUpstreamACMEWrapped(t, fmt.Sprintf("127.0.0.1:%d", solverPort), func(next http.Handler) http.Handler {
		var firstLocation string
		var firstBody []byte
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// The in-repo server mints a new account on every new-account call;
			// RFC 8555 section 7.3.1 (and every real CA) answers 200 with the
			// existing account for a known key, which is what Revoke relies on.
			if r.URL.Path == "/acme/new-account" && r.Method == http.MethodPost {
				mu.Lock()
				loc, body := firstLocation, firstBody
				mu.Unlock()
				if loc != "" {
					w.Header().Set("Location", loc)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write(body)
					return
				}
				rec := httptest.NewRecorder()
				next.ServeHTTP(rec, r)
				mu.Lock()
				firstLocation, firstBody = rec.Header().Get("Location"), rec.Body.Bytes()
				mu.Unlock()
				for k, v := range rec.Header() {
					w.Header()[k] = v
				}
				w.WriteHeader(rec.Code)
				_, _ = w.Write(rec.Body.Bytes())
				return
			}
			if r.URL.Path != "/acme/revoke-cert" {
				next.ServeHTTP(w, r)
				return
			}
			rec := httptest.NewRecorder()
			next.ServeHTTP(rec, r)
			mu.Lock()
			revokeStatus = append(revokeStatus, rec.Code)
			mu.Unlock()
			for k, v := range rec.Header() {
				w.Header()[k] = v
			}
			w.WriteHeader(rec.Code)
			_, _ = w.Write(rec.Body.Bytes())
		})
	})
	db := setupIntegrationDB(t)
	inventory, _ := newIntegrationCAProvider(t, db)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	credJSON, _ := json.Marshal(map[string]string{"account_key_pem": keyPEM})
	creds := &upstreamTestCreds{payloads: map[string]string{"acct": string(credJSON)}}

	cfg, _ := json.Marshal(acmeConnectorConfig{
		DirectoryURL: upstream + "/acme/directory", Email: "ops@example.com",
		HTTP01Listen: fmt.Sprintf("127.0.0.1:%d", solverPort),
	})
	conn := NewACMEIssuerConnector(ConnectorRecord{ID: "conn-acme-rev", Name: "n", Type: "acme", ConfigJSON: string(cfg), CredentialRef: "acct"}, inventory, creds)
	conn.(*acmeIssuerConnector).allowLoopbackForTest = true

	res, err := conn.Issue(context.Background(), connectors.IssueRequest{CSRPEM: generateTestCSRPEM(t, acmeTestHost), TeamID: "team-acme"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	rc := conn.(connectors.RevokingConnector)
	if err := rc.Revoke(context.Background(), connectors.RevokeRequest{CertificatePEM: res.CertificatePEM, Reason: 1}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(revokeStatus) != 1 || revokeStatus[0] != http.StatusOK {
		t.Fatalf("upstream revoke-cert statuses: %v", revokeStatus)
	}

	// An ephemeral account cannot revoke, and says so without calling upstream.
	noKey := NewACMEIssuerConnector(ConnectorRecord{ID: "conn-acme-eph", Name: "n", Type: "acme", ConfigJSON: string(cfg)}, inventory, nil)
	if err := noKey.(connectors.RevokingConnector).Revoke(context.Background(), connectors.RevokeRequest{CertificatePEM: res.CertificatePEM}); err == nil || !strings.Contains(err.Error(), "account_key_pem") {
		t.Fatalf("ephemeral revoke: %v", err)
	}
	if err := rc.Revoke(context.Background(), connectors.RevokeRequest{CertificatePEM: "junk"}); err == nil {
		t.Fatal("non-PEM certificate must be refused")
	}
}
