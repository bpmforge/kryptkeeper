// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func newRenewalExecuteTestMux(t *testing.T) (*http.ServeMux, CertificateProvider, ManagedTargetStore, OutboundCredentialStore, string) {
	t.Helper()
	mux, _, provider, targetStore, credStore, caID := newRenewalExecuteTestMuxAuth(t)
	return mux, provider, targetStore, credStore, caID
}

// newRenewalExecuteTestMuxAuth also returns the Authenticator, for tests that
// mint non-admin API keys.
func newRenewalExecuteTestMuxAuth(t *testing.T) (*http.ServeMux, *Authenticator, CertificateProvider, ManagedTargetStore, OutboundCredentialStore, string) {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := NewAuthenticatorFromEnv()

	certDB := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, certDB)
	caID := getFirstCAID(t, engine)

	storeDB, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "renewal-exec-handler.db"))
	if err != nil {
		t.Fatalf("open store db: %v", err)
	}
	t.Cleanup(func() { storeDB.Close() })
	targetStore := &sqliteManagedTargetStore{db: storeDB}
	if err := targetStore.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("target schema: %v", err)
	}
	credStore := &sqliteOutboundCredentialStore{db: storeDB, passphrase: []byte("handler-test-passphrase-32bytes!")}
	if err := credStore.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("cred schema: %v", err)
	}

	mux := http.NewServeMux()
	RegisterRenewalExecuteHandler(mux, auth, provider, targetStore, credStore, stubAuditProvider{})
	return mux, auth, provider, targetStore, credStore, caID
}

func postRenewalExecute(t *testing.T, mux *http.ServeMux, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/renewal/execute", bytes.NewReader(raw))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestRenewalExecuteHandlerRejectsUnauthenticated(t *testing.T) {
	mux, _, _, _, _ := newRenewalExecuteTestMux(t)
	rec := postRenewalExecute(t, mux, "", map[string]string{"fingerprint": "fp", "target_id": "tgt"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestRenewalExecuteHandlerValidatesBody(t *testing.T) {
	mux, _, _, _, _ := newRenewalExecuteTestMux(t)
	rec := postRenewalExecute(t, mux, "test-token", map[string]string{"fingerprint": ""})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRenewalExecuteHandlerUnknownCertificateIs404(t *testing.T) {
	mux, _, _, _, _ := newRenewalExecuteTestMux(t)
	rec := postRenewalExecute(t, mux, "test-token", map[string]any{
		"fingerprint": "deadbeef", "target_id": "tgt-missing",
		"install": map[string]string{"server_type": "nginx", "cert_path": "/a", "key_path": "/b"},
	})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

// End-to-end through the HTTP surface: renewal succeeds via the production
// provider; the SSH dial fails fast (pinned local port with no listener), so
// the response must report renewed=true with a visible connect_failed
// install outcome — partial state on the wire, never hidden (S-50).
func TestRenewalExecuteHandlerReportsPartialInstallFailure(t *testing.T) {
	mux, provider, targetStore, credStore, caID := newRenewalExecuteTestMux(t)
	ctx := context.Background()

	issued, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       caID,
		CSRPEM:     generateTestCSRPEM(t, "handler.example.com", "handler.example.com"),
		TemplateID: "file-backed-default",
		TeamID:     "team-handler",
	})
	if err != nil {
		t.Fatalf("issue predecessor: %v", err)
	}

	if _, err := credStore.Create(ctx, "cred-h1", "handler ssh", CredentialTypeSSHKey, "", testSSHCredentialJSON(t)); err != nil {
		t.Fatalf("create credential: %v", err)
	}
	target, err := targetStore.Create(ctx, ManagedTarget{
		ID: "tgt-h1", Name: "handler-target", Host: "127.0.0.1",
		DiscoveryMode: "none", InstallMode: "ssh", RenewalMethod: "manual",
		CredentialRef: "cred-h1",
	})
	if err != nil {
		t.Fatalf("create target: %v", err)
	}

	rec := postRenewalExecute(t, mux, "test-token", map[string]any{
		"fingerprint": issued.CertificateItem.FingerprintSHA256,
		"target_id":   target.ID,
		"install": map[string]string{
			"server_type": "nginx",
			"cert_path":   "/etc/nginx/tls/h.crt",
			"key_path":    "/etc/nginx/tls/h.key",
		},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Data RenewalExecuteResult `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Data.Renewed || resp.Data.NewFingerprint == "" {
		t.Fatalf("expected a renewed successor on the wire, got %+v", resp.Data)
	}
	if resp.Data.InstallOutcome != "connect_failed" {
		t.Fatalf("expected connect_failed (no SSH listener), got %+v", resp.Data)
	}
	// The private key must never ride the response.
	if bytes.Contains(rec.Body.Bytes(), []byte("PRIVATE KEY")) {
		t.Fatal("response leaked key material")
	}
}

func TestRenewalExecuteHandlerRejectsAgentModeTarget(t *testing.T) {
	mux, provider, targetStore, _, caID := newRenewalExecuteTestMux(t)
	ctx := context.Background()

	issued, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       caID,
		CSRPEM:     generateTestCSRPEM(t, "agentmode.example.com", "agentmode.example.com"),
		TemplateID: "file-backed-default",
		TeamID:     "team-agentmode",
	})
	if err != nil {
		t.Fatalf("issue predecessor: %v", err)
	}
	target, err := targetStore.Create(ctx, ManagedTarget{
		ID: "tgt-h2", Name: "agent-target", Host: "host.example.com",
		DiscoveryMode: "agent", InstallMode: "agent", RenewalMethod: "acme",
	})
	if err != nil {
		t.Fatalf("create target: %v", err)
	}

	rec := postRenewalExecute(t, mux, "test-token", map[string]any{
		"fingerprint": issued.CertificateItem.FingerprintSHA256,
		"target_id":   target.ID,
		"install":     map[string]string{"server_type": "nginx", "cert_path": "/a", "key_path": "/b"},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for agent-mode target, got %d: %s", rec.Code, rec.Body.String())
	}
}
