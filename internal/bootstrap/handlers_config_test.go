// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func newConfigTestMux(t *testing.T, store ConfigStore) (*http.ServeMux, *Authenticator) {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := NewAuthenticatorFromEnv()

	mux := http.NewServeMux()
	registerConfigHandlers(mux, auth, store, stubAuditProviderForCA{})
	return mux, auth
}

func newConfigTestStore(t *testing.T) ConfigStore {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "config-handler-test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	store := &sqliteConfigStore{db: db, passphrase: []byte("test-passphrase")}
	if err := store.EnsureSchema(t.Context()); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}
	return store
}

func doConfigRequest(mux *http.ServeMux, method, path, token, body string) *httptest.ResponseRecorder {
	var r *bytes.Buffer
	if body == "" {
		r = &bytes.Buffer{}
	} else {
		r = bytes.NewBufferString(body)
	}
	req := httptest.NewRequest(method, path, r)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

type configListResponse struct {
	Data []EffectiveSetting `json:"data"`
}

func findSetting(settings []EffectiveSetting, key string) (EffectiveSetting, bool) {
	for _, s := range settings {
		if s.Key == key {
			return s, true
		}
	}
	return EffectiveSetting{}, false
}

func TestConfigListHandler_RequiresAuth(t *testing.T) {
	mux, _ := newConfigTestMux(t, newConfigTestStore(t))
	rec := doConfigRequest(mux, http.MethodGet, "/api/v1/config", "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// TestConfigListHandler_DeniesPrincipalWithoutOperationalReadAccess proves
// GET /api/v1/config is gated like every other operational-summary read in
// this package (handlers_dashboard.go, handlers_notifications.go) -- not
// open to any authenticated principal, since the response surfaces SSO
// issuer, SMTP host, and discovery-provider mode.
func TestConfigListHandler_DeniesPrincipalWithoutOperationalReadAccess(t *testing.T) {
	mux, auth := newConfigTestMux(t, newConfigTestStore(t))
	_, token, err := auth.CreateAPIKey("no-ops-read", "requester-1", "requester", []string{"read:certs"}, "", "", time.Now())
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	rec := doConfigRequest(mux, http.MethodGet, "/api/v1/config", token, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s, want 403", rec.Code, rec.Body.String())
	}
}

func TestConfigListHandler_ReturnsRegistryForOperationalReadPrincipal(t *testing.T) {
	mux, _ := newConfigTestMux(t, newConfigTestStore(t))
	rec := doConfigRequest(mux, http.MethodGet, "/api/v1/config", "test-token", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp configListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Data) != len(configRegistry) {
		t.Fatalf("got %d settings, want %d", len(resp.Data), len(configRegistry))
	}
	setting, ok := findSetting(resp.Data, "discovery.provider")
	if !ok {
		t.Fatal("discovery.provider missing from response")
	}
	if setting.Source != configSourceUnset {
		t.Errorf("Source = %q, want %q", setting.Source, configSourceUnset)
	}
}

func TestConfigListHandler_StoreUnavailable(t *testing.T) {
	mux, _ := newConfigTestMux(t, nil)
	rec := doConfigRequest(mux, http.MethodGet, "/api/v1/config", "test-token", "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestConfigSetHandler_RequiresAuth(t *testing.T) {
	mux, _ := newConfigTestMux(t, newConfigTestStore(t))
	rec := doConfigRequest(mux, http.MethodPut, "/api/v1/config/discovery.provider", "", `{"value":"network"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestConfigSetHandler_RequiresAdminRole(t *testing.T) {
	mux, auth := newConfigTestMux(t, newConfigTestStore(t))
	_, token, err := auth.CreateAPIKey("non-admin", "team-1", "service-account", []string{"read:certs"}, "", "", time.Now())
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	rec := doConfigRequest(mux, http.MethodPut, "/api/v1/config/discovery.provider", token, `{"value":"network"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s, want 403", rec.Code, rec.Body.String())
	}
}

func TestConfigSetHandler_UnknownKeyReturns404(t *testing.T) {
	mux, _ := newConfigTestMux(t, newConfigTestStore(t))
	rec := doConfigRequest(mux, http.MethodPut, "/api/v1/config/not.a.real.key", "test-token", `{"value":"x"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, body = %s, want 404", rec.Code, rec.Body.String())
	}
}

// TestConfigSetHandler_NonSecretRoundTrip proves write -> read reflects
// immediately through the real HTTP handlers with no restart-equivalent
// step in between (acceptance: "no server restart needed").
func TestConfigSetHandler_NonSecretRoundTrip(t *testing.T) {
	mux, _ := newConfigTestMux(t, newConfigTestStore(t))

	rec := doConfigRequest(mux, http.MethodPut, "/api/v1/config/notifications.smtp_host", "test-token", `{"value":"smtp.example.com"}`)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("PUT status = %d, body = %s, want 204", rec.Code, rec.Body.String())
	}

	rec = doConfigRequest(mux, http.MethodGet, "/api/v1/config", "test-token", "")
	var resp configListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	setting, ok := findSetting(resp.Data, "notifications.smtp_host")
	if !ok {
		t.Fatal("notifications.smtp_host missing from response")
	}
	if setting.Source != configSourceDatabase {
		t.Errorf("Source = %q, want %q", setting.Source, configSourceDatabase)
	}
	if setting.Value != "smtp.example.com" {
		t.Errorf("Value = %q, want %q", setting.Value, "smtp.example.com")
	}
}

// TestConfigSetHandler_SecretNeverEchoedOrListed is the discriminating test
// for acceptance #2 at the HTTP layer: setting a secret must not return the
// value in the PUT response, and the subsequent GET must report presence
// only, never the plaintext.
func TestConfigSetHandler_SecretNeverEchoedOrListed(t *testing.T) {
	mux, _ := newConfigTestMux(t, newConfigTestStore(t))
	const plaintextMarker = "R0ROUTINGKEYSECRET"

	rec := doConfigRequest(mux, http.MethodPut, "/api/v1/config/notifications.pagerduty_routing_key", "test-token",
		`{"value":"`+plaintextMarker+`"}`)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("PUT status = %d, body = %s, want 204", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), plaintextMarker) {
		t.Fatalf("PUT response echoed the secret: %s", rec.Body.String())
	}

	rec = doConfigRequest(mux, http.MethodGet, "/api/v1/config", "test-token", "")
	if strings.Contains(rec.Body.String(), plaintextMarker) {
		t.Fatalf("GET response leaked the secret: %s", rec.Body.String())
	}
	var resp configListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	setting, ok := findSetting(resp.Data, "notifications.pagerduty_routing_key")
	if !ok {
		t.Fatal("notifications.pagerduty_routing_key missing from response")
	}
	if !setting.Configured {
		t.Error("expected Configured = true after a successful PUT")
	}
	if setting.Value != "" {
		t.Errorf("Value = %q, want empty for a secret key", setting.Value)
	}
}

func TestConfigDeleteHandler_RequiresAdminRole(t *testing.T) {
	mux, auth := newConfigTestMux(t, newConfigTestStore(t))
	_, token, err := auth.CreateAPIKey("non-admin", "team-1", "service-account", []string{"read:certs"}, "", "", time.Now())
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	rec := doConfigRequest(mux, http.MethodDelete, "/api/v1/config/discovery.provider", token, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestConfigDeleteHandler_NoOverrideReturns404(t *testing.T) {
	mux, _ := newConfigTestMux(t, newConfigTestStore(t))
	rec := doConfigRequest(mux, http.MethodDelete, "/api/v1/config/discovery.provider", "test-token", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestConfigDeleteHandler_ResetsToEnvDefault(t *testing.T) {
	t.Setenv("APP_DISCOVERY_PROVIDER", "cloud")
	mux, _ := newConfigTestMux(t, newConfigTestStore(t))

	rec := doConfigRequest(mux, http.MethodPut, "/api/v1/config/discovery.provider", "test-token", `{"value":"network"}`)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("PUT status = %d, want 204", rec.Code)
	}
	rec = doConfigRequest(mux, http.MethodDelete, "/api/v1/config/discovery.provider", "test-token", "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE status = %d, body = %s, want 204", rec.Code, rec.Body.String())
	}

	rec = doConfigRequest(mux, http.MethodGet, "/api/v1/config", "test-token", "")
	var resp configListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	setting, ok := findSetting(resp.Data, "discovery.provider")
	if !ok {
		t.Fatal("discovery.provider missing from response")
	}
	if setting.Source != configSourceEnvDefault {
		t.Errorf("Source = %q, want %q (env default should show through after reset)", setting.Source, configSourceEnvDefault)
	}
	if setting.Value != "cloud" {
		t.Errorf("Value = %q, want %q", setting.Value, "cloud")
	}
}

func TestConfigHandlers_UnknownPathSegmentReturns404(t *testing.T) {
	mux, _ := newConfigTestMux(t, newConfigTestStore(t))
	rec := doConfigRequest(mux, http.MethodGet, "/api/v1/config/", "test-token", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}
