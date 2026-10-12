// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"kryptkeeper/internal/agentdiscovery"
)

// The properties a credential API must not lose: plaintext goes in and
// NEVER comes back out, and only admins touch it at all.

func credentialsTestMux(t *testing.T) (*http.ServeMux, *sqliteOutboundCredentialStore) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "credentials-handler.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	store := &sqliteOutboundCredentialStore{db: db, passphrase: []byte("handler-test-passphrase-32bytes!")}
	if err := store.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("schema: %v", err)
	}
	mux := http.NewServeMux()
	registerCredentialHandlers(mux, newReportsTestAuth(t), store, stubAuditProvider{}, nil)
	return mux, store
}

func TestCredentialCreateNeverEchoesTheSecret(t *testing.T) {
	mux, store := credentialsTestMux(t)
	secret := "-----BEGIN OPENSSH PRIVATE KEY-----\nsuper-secret-material\n-----END" // secret-scan:allow fake fixture
	body, _ := json.Marshal(map[string]any{
		"name":            "prod fleet ssh",
		"credential_type": "ssh_key",
		"payload":         map[string]string{"user": "root", "private_key_pem": secret},
	})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/credentials", body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	// The one property that must hold above all others.
	if strings.Contains(rec.Body.String(), "super-secret-material") {
		t.Fatal("the create response echoed the secret payload")
	}
	var resp struct{ Data OutboundCredentialMeta }
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Data.ID == "" || resp.Data.CredentialType != "ssh_key" {
		t.Fatalf("metadata wrong: %+v", resp.Data)
	}
	// And the stored material must be the real thing, resolvable internally.
	got, err := store.Resolve(context.Background(), resp.Data.ID)
	if err != nil || !strings.Contains(string(got), "super-secret-material") {
		t.Fatalf("stored payload wrong: %v %s", err, got)
	}
	// List: metadata only, no secret.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/credentials", nil))
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "super-secret-material") {
		t.Fatalf("list leaked or failed: %d", rec.Code)
	}
}

func TestCredentialWindowsPasswordRoundTripsThroughTheAPI(t *testing.T) {
	mux, store := credentialsTestMux(t)
	body, _ := json.Marshal(map[string]any{
		"name":            "iis-web-01 winrm",
		"credential_type": "windows_password",
		"payload": map[string]string{
			"base_url": "https://iis-web-01.corp.example.com:5986/wsman",
			"username": "CORP\\svc-pki", "password": "s3cret", "ipport": "0.0.0.0:443",
		},
	})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/credentials", body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("windows_password must be creatable over the API: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct{ Data OutboundCredentialMeta }
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	got, _ := store.Resolve(context.Background(), resp.Data.ID)
	var payload struct {
		BaseURL string `json:"base_url"`
		IPPort  string `json:"ipport"`
	}
	if err := json.Unmarshal(got, &payload); err != nil || payload.BaseURL == "" || payload.IPPort == "" {
		t.Fatalf("payload did not survive: %v %s", err, got)
	}
}

func TestCredentialRejectsUnknownTypeAndBadBody(t *testing.T) {
	mux, _ := credentialsTestMux(t)
	body, _ := json.Marshal(map[string]any{
		"name": "x", "credential_type": "carrier_pigeon", "payload": map[string]string{"a": "b"},
	})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/credentials", body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown type must be refused, got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/credentials", []byte(`{"name":"x"}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing payload must be refused, got %d", rec.Code)
	}
}

func TestCredentialDeleteAndAuth(t *testing.T) {
	mux, store := credentialsTestMux(t)
	meta, err := store.Create(context.Background(), "cred-del", "doomed", CredentialTypeAPIToken, "", []byte(`{}`))
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodDelete, "/api/v1/credentials/"+meta.ID, nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodDelete, "/api/v1/credentials/"+meta.ID, nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("double delete must 404, got %d", rec.Code)
	}
	// Unauthenticated is refused everywhere.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/credentials", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

// An unconfigured store must explain itself, not 500 or NPE.
func TestCredentialUnconfiguredStoreNames503(t *testing.T) {
	mux := http.NewServeMux()
	registerCredentialHandlers(mux, newReportsTestAuth(t), nil, stubAuditProvider{}, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/credentials", nil))
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "APP_CREDENTIAL_STORE_PASSPHRASE") {
		t.Fatalf("must 503 naming the config, got %d: %s", rec.Code, rec.Body.String())
	}
}

// W18-11: the preflight says what the credential can do, resolves the
// secret only inside the process, and never echoes it.
func TestCredentialPreflightReportsLevelWithoutLeakingSecret(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "preflight.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	store := &sqliteOutboundCredentialStore{db: db, passphrase: []byte("handler-test-passphrase-32bytes!")}
	_ = store.EnsureSchema(context.Background())
	var seen agentdiscovery.WinRMConfig
	fake := func(_ context.Context, cfg agentdiscovery.WinRMConfig) agentdiscovery.WinRMPreflight {
		seen = cfg
		return agentdiscovery.WinRMPreflight{Level: agentdiscovery.PreflightDiscover, CanDiscover: true, Detail: "standard token"}
	}
	mux := http.NewServeMux()
	registerCredentialHandlers(mux, newReportsTestAuth(t), store, stubAuditProvider{}, fake)

	win, _ := store.Create(context.Background(), "cred-win", "iis", CredentialTypeWindowsPassword, "",
		[]byte(`{"base_url":"https://iis:5986/wsman","username":"kktest","password":"hunter2-secret"}`))
	tok, _ := store.Create(context.Background(), "cred-tok", "f5", CredentialTypeAPIToken, "", []byte(`{"token":"t"}`))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/credentials/"+win.ID+"/preflight", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "hunter2") {
		t.Fatal("the preflight response echoed the password")
	}
	var resp struct {
		Data struct {
			CredentialID string `json:"credential_id"`
			Level        string `json:"level"`
			CanDiscover  bool   `json:"can_discover"`
			CanInstall   bool   `json:"can_install"`
		}
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Data.Level != "discover" || !resp.Data.CanDiscover || resp.Data.CanInstall || resp.Data.CredentialID != win.ID {
		t.Fatalf("verdict wrong: %+v", resp.Data)
	}
	if seen.EndpointURL != "https://iis:5986/wsman" || seen.Username != "kktest" || seen.Password != "hunter2-secret" {
		t.Fatalf("the probe did not receive the resolved credential: %+v", seen)
	}

	// Only windows_password credentials have a WinRM preflight.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/credentials/"+tok.ID+"/preflight", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("api_token preflight must be 400, got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/credentials/nope/preflight", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown id must be 404, got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/credentials/"+win.ID+"/preflight", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated must be 401, got %d", rec.Code)
	}
}
