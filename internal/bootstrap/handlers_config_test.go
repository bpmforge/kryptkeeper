// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
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

// ---- W33-06 SSO break-glass guard ------------------------------------------

func withLocalAdmin(auth *Authenticator) {
	auth.config.loginEnabled = true
	auth.config.loginUser = loginCredential{Email: "admin@example.com", PasswordHash: "hash", Role: "pki-admin", Subject: "team-1", Active: true}
}

type oidcStub struct {
	url  string
	hits int
	mode string
}

func newOIDCStub(t *testing.T) *oidcStub {
	t.Helper()
	st := &oidcStub{mode: "ok"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st.hits++
		switch st.mode {
		case "500":
			w.WriteHeader(500)
		case "mismatch":
			_, _ = w.Write([]byte(`{"issuer":"https://evil.example","jwks_uri":"https://x/jwks"}`))
		case "nojwks":
			_, _ = w.Write([]byte(`{"issuer":"` + st.url + `"}`))
		case "redirect":
			http.Redirect(w, r, "http://169.254.169.254/", http.StatusFound)
		default:
			_, _ = w.Write([]byte(`{"issuer":"` + st.url + `/","jwks_uri":"` + st.url + `/jwks"}`))
		}
	}))
	t.Cleanup(srv.Close)
	st.url = srv.URL
	prev := oidcProbeClient
	c := *srv.Client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	oidcProbeClient = &c
	t.Cleanup(func() { oidcProbeClient = prev })
	return st
}

func TestSSOGuard_RejectsWithoutLocalAdmin(t *testing.T) {
	store := newConfigTestStore(t)
	mux, _ := newConfigTestMux(t, store)
	rec := doConfigRequest(mux, http.MethodPut, "/api/v1/config/sso.oidc_audience", "test-token", `{"value":"aud"}`)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "local admin") {
		t.Fatalf("PUT = %d %s", rec.Code, rec.Body)
	}
	if _, ok, _ := store.Get(t.Context(), "sso.oidc_audience"); ok {
		t.Fatal("override persisted despite 409")
	}
}

func TestSSOGuard_DiscoveryFailureBlocksSave(t *testing.T) {
	store := newConfigTestStore(t)
	mux, auth := newConfigTestMux(t, store)
	withLocalAdmin(auth)
	auth.configStore = store
	st := newOIDCStub(t)
	body := `{"value":"` + st.url + `"}`

	for _, mode := range []string{"500", "mismatch", "nojwks", "redirect"} {
		st.mode = mode
		rec := doConfigRequest(mux, http.MethodPut, "/api/v1/config/sso.oidc_issuer", "test-token", body)
		if rec.Code != http.StatusConflict {
			t.Fatalf("%s: PUT = %d %s", mode, rec.Code, rec.Body)
		}
		if _, ok, _ := store.Get(t.Context(), "sso.oidc_issuer"); ok {
			t.Fatalf("%s: override persisted despite 409", mode)
		}
	}
	st.mode = "ok"
	if rec := doConfigRequest(mux, http.MethodPut, "/api/v1/config/sso.oidc_issuer", "test-token", body); rec.Code != http.StatusNoContent {
		t.Fatalf("valid doc PUT = %d %s", rec.Code, rec.Body)
	}
	// A bad discovery URL override is also probed against the effective issuer.
	st.mode = "500"
	if rec := doConfigRequest(mux, http.MethodPut, "/api/v1/config/sso.oidc_discovery_url", "test-token", `{"value":"`+st.url+`/d"}`); rec.Code != http.StatusConflict {
		t.Fatalf("discovery url PUT = %d", rec.Code)
	}
}

func TestSSOGuard_ProbeRefusesNonHTTPSAndInternalTargets(t *testing.T) {
	for _, u := range []string{"http://idp.example/.well-known/openid-configuration", "file:///etc/passwd", "ftp://x/y", "gopher://x"} {
		if err := probeOIDCDiscovery(t.Context(), "https://idp.example", u); !errors.Is(err, errSSOGuardDiscovery) {
			t.Fatalf("%s: err = %v", u, err)
		}
	}
	// The real (default) client refuses link-local metadata and loopback.
	for _, u := range []string{"https://169.254.169.254/latest", "https://127.0.0.1:1/x", "https://[::1]:1/x"} {
		if err := probeOIDCDiscovery(t.Context(), "https://idp.example", u); !errors.Is(err, errSSOGuardDiscovery) {
			t.Fatalf("%s: err = %v", u, err)
		}
	}
}

func TestSSOGuard_ClearingIssuerAllowed(t *testing.T) {
	store := newConfigTestStore(t)
	mux, auth := newConfigTestMux(t, store)
	withLocalAdmin(auth)
	auth.configStore = store
	st := newOIDCStub(t)
	if rec := doConfigRequest(mux, http.MethodPut, "/api/v1/config/sso.oidc_issuer", "test-token", `{"value":""}`); rec.Code != http.StatusNoContent {
		t.Fatalf("clear = %d %s", rec.Code, rec.Body)
	}
	if st.hits != 0 {
		t.Fatalf("probe called %d times for a clear", st.hits)
	}
}

func TestSSOGuard_DeleteAlwaysAllowed(t *testing.T) {
	store := newConfigTestStore(t)
	mux, auth := newConfigTestMux(t, store)
	if err := store.Set(t.Context(), "sso.oidc_issuer", "https://bad.example", "seed"); err != nil {
		t.Fatal(err)
	}
	if auth.hasEnabledLocalAdmin() {
		t.Fatal("test precondition: no local admin")
	}
	if rec := doConfigRequest(mux, http.MethodDelete, "/api/v1/config/sso.oidc_issuer", "test-token", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE = %d %s", rec.Code, rec.Body)
	}
}

func TestSSOGuard_NonGuardedKeyUnaffected(t *testing.T) {
	store := newConfigTestStore(t)
	mux, _ := newConfigTestMux(t, store)
	if rec := doConfigRequest(mux, http.MethodPut, "/api/v1/config/notifications.smtp_host", "test-token", `{"value":"smtp.example.com"}`); rec.Code != http.StatusNoContent {
		t.Fatalf("PUT = %d %s", rec.Code, rec.Body)
	}
}

func TestSSOGuard_RefusalIsAudited(t *testing.T) {
	store := newConfigTestStore(t)
	audit := &memAuditProvider{}
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	mux := http.NewServeMux()
	registerConfigHandlers(mux, NewAuthenticatorFromEnv(), store, audit)
	if rec := doConfigRequest(mux, http.MethodPut, "/api/v1/config/sso.oidc_jwks_json", "test-token", `{"value":"{}"}`); rec.Code != http.StatusConflict {
		t.Fatalf("PUT = %d", rec.Code)
	}
	rows := audit.actions("config.set")
	if len(rows) != 1 || rows[0].Outcome != AuditOutcomeFailure {
		t.Fatalf("audit rows = %+v", rows)
	}
}

func TestSSOGuard_BreakGlassEndToEnd(t *testing.T) {
	e := newBGLoginEnv(t) // local admin admin@example.com / "pw", break-glass flagged
	store := newConfigTestStore(t)
	e.auth.configStore = store
	registerConfigHandlers(e.mux, e.auth, store, e.audit)

	// A prior bad save (simulated directly against the store).
	if err := store.Set(t.Context(), "sso.oidc_issuer", "https://dead.invalid", "seed"); err != nil {
		t.Fatal(err)
	}
	rec := e.login("admin@example.com", "pw")
	if rec.Code != http.StatusOK {
		t.Fatalf("breakglass login = %d %s", rec.Code, rec.Body)
	}
	tok := bgDecode[struct {
		AccessToken string `json:"access_token"`
	}](t, rec).AccessToken
	if tok == "" {
		t.Fatal("no token")
	}
	if rec := doConfigRequest(e.mux, http.MethodDelete, "/api/v1/config/sso.oidc_issuer", tok, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE = %d %s", rec.Code, rec.Body)
	}
	rec = doConfigRequest(e.mux, http.MethodGet, "/api/v1/config", tok, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d %s", rec.Code, rec.Body)
	}
	var list configListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if s, ok := findSetting(list.Data, "sso.oidc_issuer"); !ok || s.EffectiveSource != "env" {
		t.Fatalf("sso.oidc_issuer = %+v", s)
	}
}

type recordingConfigAudit struct {
	stubAuditProviderForCA
	mu      sync.Mutex
	entries []AuditEntry
}

func (a *recordingConfigAudit) AppendEntry(_ context.Context, e AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, e)
	return nil
}

func (a *recordingConfigAudit) has(action string, outcome AuditOutcome) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, e := range a.entries {
		if e.Action == action && e.Outcome == outcome {
			return true
		}
	}
	return false
}

func newRecordingConfigMux(t *testing.T) (*http.ServeMux, *Authenticator, *recordingConfigAudit) {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := NewAuthenticatorFromEnv()
	rec := &recordingConfigAudit{}
	mux := http.NewServeMux()
	registerConfigHandlers(mux, auth, newConfigTestStore(t), rec)
	return mux, auth, rec
}

func newRecordingConfigMuxWithStore(t *testing.T, store ConfigStore) (*http.ServeMux, *Authenticator, *recordingConfigAudit) {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := NewAuthenticatorFromEnv()
	rec := &recordingConfigAudit{}
	mux := http.NewServeMux()
	registerConfigHandlers(mux, auth, store, rec)
	return mux, auth, rec
}

func TestSLOObjectiveUpdateIsAudited(t *testing.T) {
	mux, _, rec := newRecordingConfigMux(t)
	path := "/api/v1/config/slo.renewal_success_objective"

	if r := doConfigRequest(mux, http.MethodPut, path, "test-token", `{"value":"0.97"}`); r.Code != http.StatusNoContent {
		t.Fatalf("PUT status = %d, body = %s", r.Code, r.Body.String())
	}
	if !rec.has("config.set", AuditOutcomeSuccess) || !rec.has("slo.objective.update", AuditOutcomeSuccess) {
		t.Fatalf("admin PUT must audit config.set and slo.objective.update: %+v", rec.entries)
	}
	if r := doConfigRequest(mux, http.MethodDelete, path, "test-token", ""); r.Code != http.StatusNoContent {
		t.Fatalf("DELETE status = %d", r.Code)
	}
	if !rec.has("config.reset", AuditOutcomeSuccess) {
		t.Fatalf("reset must audit config.reset: %+v", rec.entries)
	}

	mux2, auth2, rec2 := newRecordingConfigMux(t)
	_, token, err := auth2.CreateAPIKey("non-admin", "team-1", "service-account", []string{"read:certs"}, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if r := doConfigRequest(mux2, http.MethodPut, path, token, `{"value":"0.97"}`); r.Code != http.StatusForbidden {
		t.Fatalf("non-admin status = %d, want 403", r.Code)
	}
	if !rec2.has("config.set", AuditOutcomeDenied) || rec2.has("slo.objective.update", AuditOutcomeSuccess) {
		t.Fatalf("denied PUT must audit only config.set denied: %+v", rec2.entries)
	}
}

func TestInvalidObjectiveIs400(t *testing.T) {
	mux, _, rec := newRecordingConfigMux(t)
	r := doConfigRequest(mux, http.MethodPut, "/api/v1/config/slo.issuance_success_objective", "test-token", `{"value":"1"}`)
	if r.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", r.Code)
	}
	if !rec.has("config.set", AuditOutcomeFailure) || rec.has("slo.objective.update", AuditOutcomeSuccess) {
		t.Fatalf("rejected value must audit config.set failure only: %+v", rec.entries)
	}
}
