// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newAPIKeyTestAuth(t *testing.T) *Authenticator {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "admin-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	return NewAuthenticatorFromEnv()
}

func newAPIKeyTestMux(t *testing.T) (*http.ServeMux, *Authenticator) {
	t.Helper()
	auth := newAPIKeyTestAuth(t)
	mux := http.NewServeMux()
	registerAuthHandlers(mux, auth, stubAuditProvider{})
	return mux, auth
}

// --- Unit tests for API key management methods ---

func TestCreateAPIKeyReturnsTokenAndRecord(t *testing.T) {
	auth := newAPIKeyTestAuth(t)
	record, token, err := auth.CreateAPIKey("ci-bot", "team-1", "service-account", []string{"read:certs"}, "", "", time.Now())
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	if token == "" || !strings.HasPrefix(token, "kk_") {
		t.Errorf("unexpected token format %q", token)
	}
	if record.Kid == "" {
		t.Error("expected non-empty Kid")
	}
	if record.PrincipalID != "team-1" {
		t.Errorf("unexpected principal %q", record.PrincipalID)
	}
	if record.Role != "service-account" {
		t.Errorf("unexpected role %q", record.Role)
	}
	if len(record.Scopes) != 1 || record.Scopes[0] != "read:certs" {
		t.Errorf("unexpected scopes %v", record.Scopes)
	}
	if !record.Active {
		t.Error("expected active=true")
	}
}

func TestCreateAPIKeyDefaultsRoleToServiceAccount(t *testing.T) {
	auth := newAPIKeyTestAuth(t)
	record, _, err := auth.CreateAPIKey("no-role", "team-1", "", nil, "", "", time.Now())
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	if record.Role != "service-account" {
		t.Errorf("expected default role service-account, got %q", record.Role)
	}
}

func TestCreateAPIKeyRejectsEmptyPrincipal(t *testing.T) {
	auth := newAPIKeyTestAuth(t)
	_, _, err := auth.CreateAPIKey("name", "", "service-account", nil, "", "", time.Now())
	if err == nil {
		t.Error("expected error for empty principalID")
	}
}

func TestCreateAPIKeyRejectsInvalidExpiry(t *testing.T) {
	auth := newAPIKeyTestAuth(t)
	_, _, err := auth.CreateAPIKey("name", "team-1", "service-account", nil, "not-a-date", "", time.Now())
	if err == nil {
		t.Error("expected error for invalid expiry")
	}
}

func TestListAPIKeys(t *testing.T) {
	auth := newAPIKeyTestAuth(t)
	now := time.Now()
	auth.CreateAPIKey("key-a", "p1", "service-account", nil, "", "", now)
	auth.CreateAPIKey("key-b", "p2", "service-account", nil, "", "", now)

	keys := auth.ListAPIKeys()
	if len(keys) < 2 {
		t.Errorf("expected at least 2 keys, got %d", len(keys))
	}
	// Verify no secret verifiers leak out.
	for _, k := range keys {
		if strings.Contains(k.SecretVerifier, "sk_") {
			t.Errorf("secret verifier leaked in list: %q", k.SecretVerifier)
		}
	}
}

func TestRevokeAPIKey(t *testing.T) {
	auth := newAPIKeyTestAuth(t)
	record, _, _ := auth.CreateAPIKey("temp-key", "p1", "service-account", nil, "", "", time.Now())

	if found, err := auth.RevokeAPIKey(record.Kid); !found || err != nil {
		t.Error("expected RevokeAPIKey to find existing key")
	}
	// Second delete returns false.
	if found, _ := auth.RevokeAPIKey(record.Kid); found {
		t.Error("expected RevokeAPIKey to return false for already-deleted key")
	}
	// Empty kid returns false.
	if found, _ := auth.RevokeAPIKey(""); found {
		t.Error("expected RevokeAPIKey to return false for empty kid")
	}
}

func TestCreatedAPIKeyCanAuthenticate(t *testing.T) {
	auth := newAPIKeyTestAuth(t)
	_, token, err := auth.CreateAPIKey("svc", "svc-1", "service-account", nil, "", "", time.Now())
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/authz-check", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	principal, err := auth.AuthenticatePrincipal(req, time.Now())
	if err != nil {
		t.Fatalf("authenticate with new key: %v", err)
	}
	if principal != "svc-1" {
		t.Errorf("unexpected principal %q", principal)
	}
}

func TestDeletedAPIKeyCannotAuthenticate(t *testing.T) {
	auth := newAPIKeyTestAuth(t)
	record, token, _ := auth.CreateAPIKey("svc", "svc-1", "service-account", nil, "", "", time.Now())
	_, _ = auth.RevokeAPIKey(record.Kid)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/authz-check", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	if _, err := auth.AuthenticatePrincipal(req, time.Now()); err == nil {
		t.Error("expected authentication to fail after key deletion")
	}
}

func TestIsAdminRole(t *testing.T) {
	if !isAdminRole("pki-admin") {
		t.Error("expected pki-admin to be admin role")
	}
	if isAdminRole("pki-operator") {
		t.Error("expected pki-operator to not be admin role")
	}
	if isAdminRole("") {
		t.Error("expected empty to not be admin role")
	}
}

// --- HTTP handler tests ---

func TestAPIKeyHandlerListRequiresAuth(t *testing.T) {
	mux, _ := newAPIKeyTestMux(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/api-keys", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestAPIKeyHandlerCreateAndList(t *testing.T) {
	mux, _ := newAPIKeyTestMux(t)

	// Create a key.
	body, _ := json.Marshal(map[string]any{
		"name":         "ci-bot",
		"principal_id": "team-1",
		"role":         "service-account",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-keys", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer admin-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("create api-key: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Data struct {
			Token string `json:"token"`
			Kid   string `json:"kid"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if !strings.HasPrefix(created.Data.Token, "kk_") {
		t.Errorf("unexpected token format %q", created.Data.Token)
	}

	// List keys — should include the newly created one.
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/api-keys", nil)
	req2.Header.Set("Authorization", "Bearer admin-token")
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("list api-keys: expected 200, got %d", rec2.Code)
	}
	var listed struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec2.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode list response: %v (body: %s)", err, rec2.Body.String())
	}
	if len(listed.Data) < 1 {
		t.Errorf("expected at least 1 key in list, got %d (body: %s)", len(listed.Data), rec2.Body.String())
	}
}

func TestAPIKeyHandlerDeleteKey(t *testing.T) {
	mux, auth := newAPIKeyTestMux(t)

	// Create a key directly via auth.
	record, _, _ := auth.CreateAPIKey("temp", "p1", "service-account", nil, "", "", time.Now())

	// Delete via handler.
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/api-keys/"+record.Kid, nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete api-key: expected 204, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify deleted.
	keys := auth.ListAPIKeys()
	for _, k := range keys {
		if k.Kid == record.Kid {
			t.Error("key still present after delete")
		}
	}
}
