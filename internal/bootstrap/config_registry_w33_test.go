// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestConfigRegistry_SAMLSCIMKeyBackendKeys(t *testing.T) {
	for _, key := range []string{
		"saml.sp_entity_id", "saml.idp_sso_url", "saml.idp_issuer", "saml.idp_certificate",
		"scim.enabled", "scim.token", "key_backend.kind", "key_backend.pkcs11_module",
	} {
		if _, ok := lookupConfigKey(key); !ok {
			t.Errorf("key %q not registered", key)
		}
	}
	if def, _ := lookupConfigKey("scim.token"); !def.Secret {
		t.Error("scim.token must be Secret")
	}
	for _, key := range []string{"key_backend.kind", "key_backend.pkcs11_module"} {
		if def, _ := lookupConfigKey(key); !def.RestartRequired {
			t.Errorf("%s must be RestartRequired", key)
		}
	}
	if _, ok := lookupConfigKey("saml.metadata_url"); ok {
		t.Error("saml.metadata_url must not be registered (no consumer)")
	}
}

func TestSAMLOverrideLiveWithinTTL(t *testing.T) {
	_, cert := generateTestSAMLIDPCert(t)
	store := newConfigTestStore(t)
	clock := time.Now()
	auth := &Authenticator{
		config:       testSAMLSPConfig(cert),
		configStore:  store,
		ssoConfigNow: func() time.Time { return clock },
	}
	ctx := context.Background()
	envURL := auth.config.samlIDPSSOURL

	if got := samlServiceProviderFromConfig(auth.samlEffectiveConfig(ctx)).IdentityProviderSSOURL; got != envURL {
		t.Fatalf("pre-override URL = %q, want env %q", got, envURL)
	}
	const override = "https://override-idp.example.com/sso"
	if err := store.Set(ctx, "saml.idp_sso_url", override, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := store.Set(ctx, "saml.sp_entity_id", "https://override-sp.example.com", "admin"); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(10 * time.Second)
	if got := samlServiceProviderFromConfig(auth.samlEffectiveConfig(ctx)).IdentityProviderSSOURL; got != envURL {
		t.Fatalf("inside TTL URL = %q, want cached env %q", got, envURL)
	}
	clock = clock.Add(31 * time.Second)
	sp := samlServiceProviderFromConfig(auth.samlEffectiveConfig(ctx))
	if sp.IdentityProviderSSOURL != override || sp.ServiceProviderIssuer != "https://override-sp.example.com" {
		t.Fatalf("after TTL got url=%q issuer=%q", sp.IdentityProviderSSOURL, sp.ServiceProviderIssuer)
	}
	// Non-https override is rejected (SP disabled), same as the env rule.
	if err := store.Set(ctx, "saml.idp_sso_url", "http://insecure.example.com", "admin"); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(31 * time.Second)
	if samlServiceProviderFromConfig(auth.samlEffectiveConfig(ctx)) != nil {
		t.Fatal("http IdP SSO URL override must disable SAML")
	}
}

func TestSCIMTokenOverrideLive(t *testing.T) {
	store := newConfigTestStore(t)
	clock := time.Now()
	auth := &Authenticator{
		config:       authValidatorConfig{scimBearerToken: "env-token"},
		configStore:  store,
		ssoConfigNow: func() time.Time { return clock },
	}
	ctx := context.Background()
	req := func(tok string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		return r
	}
	advance := func() { clock = clock.Add(31 * time.Second) }

	if !scimAuthorized(auth, req("env-token")) {
		t.Fatal("env token should authorize before override")
	}
	if err := store.Set(ctx, "scim.token", "override-token", "admin"); err != nil {
		t.Fatal(err)
	}
	advance()
	if !scimAuthorized(auth, req("override-token")) || scimAuthorized(auth, req("env-token")) {
		t.Fatal("after TTL override token must replace env token")
	}
	// scim.enabled=false disables SCIM even with a token.
	if err := store.Set(ctx, "scim.enabled", "false", "admin"); err != nil {
		t.Fatal(err)
	}
	advance()
	if scimAuthorized(auth, req("override-token")) {
		t.Fatal("scim.enabled=false must deny")
	}
	// Reset restores env behaviour.
	for _, k := range []string{"scim.enabled", "scim.token"} {
		if err := store.Delete(ctx, k); err != nil {
			t.Fatal(err)
		}
	}
	advance()
	if !scimAuthorized(auth, req("env-token")) || scimAuthorized(auth, req("override-token")) {
		t.Fatal("DELETE must restore the env token")
	}
	// Enabled with no token fails closed.
	t.Setenv("APP_SCIM_ENABLED", "true")
	empty := &Authenticator{config: authValidatorConfig{}}
	if scimAuthorized(empty, req("anything")) {
		t.Fatal("enabled with empty token must deny")
	}
}

func TestConfigGet_NoSecretBytes(t *testing.T) {
	mux, _ := newConfigTestMux(t, newConfigTestStore(t))
	const secret = "s3cr3t-token-xyz"
	rec := doConfigRequest(mux, http.MethodPut, "/api/v1/config/scim.token", "test-token", `{"value":"`+secret+`"}`)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("PUT = %d %s", rec.Code, rec.Body.String())
	}
	rec = doConfigRequest(mux, http.MethodGet, "/api/v1/config", "test-token", "")
	if strings.Contains(rec.Body.String(), secret) {
		t.Fatal("GET /config leaked the SCIM token")
	}
	var resp configListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	s, ok := findSetting(resp.Data, "scim.token")
	if !ok || !s.Configured || s.Value != "" || s.EffectiveSource != "override" {
		t.Fatalf("scim.token row = %+v", s)
	}
}

func TestEffectiveSourceEnvOverride(t *testing.T) {
	mux, _ := newConfigTestMux(t, newConfigTestStore(t))
	get := func(key string) EffectiveSetting {
		rec := doConfigRequest(mux, http.MethodGet, "/api/v1/config", "test-token", "")
		var resp configListResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		s, ok := findSetting(resp.Data, key)
		if !ok {
			t.Fatalf("%s missing", key)
		}
		return s
	}
	const key = "saml.idp_issuer"
	if s := get(key); s.EffectiveSource != "env" || s.Source != configSourceUnset {
		t.Fatalf("unset: %+v", s)
	}
	t.Setenv("APP_SAML_IDP_ISSUER", "https://env-idp")
	if s := get(key); s.EffectiveSource != "env" || s.Value != "https://env-idp" {
		t.Fatalf("env: %+v", s)
	}
	if rec := doConfigRequest(mux, http.MethodPut, "/api/v1/config/"+key, "test-token", `{"value":"https://db-idp"}`); rec.Code != http.StatusNoContent {
		t.Fatalf("PUT = %d", rec.Code)
	}
	if s := get(key); s.EffectiveSource != "override" || s.Value != "https://db-idp" {
		t.Fatalf("override: %+v", s)
	}
	if rec := doConfigRequest(mux, http.MethodDelete, "/api/v1/config/"+key, "test-token", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE = %d", rec.Code)
	}
	if s := get(key); s.EffectiveSource != "env" || s.Value != "https://env-idp" {
		t.Fatalf("after reset: %+v", s)
	}
	if s := get("key_backend.kind"); !s.RestartRequired {
		t.Fatalf("key_backend.kind restart_required not reported: %+v", s)
	}
}

func TestConfigAuditCarriesActorAndKey(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := NewAuthenticatorFromEnv()
	audit := &recordingConfigAudit{}
	mux := http.NewServeMux()
	registerConfigHandlers(mux, auth, newConfigTestStore(t), audit)

	const key = "key_backend.kind"
	doConfigRequest(mux, http.MethodPut, "/api/v1/config/"+key, "test-token", `{"value":"pkcs11"}`)
	doConfigRequest(mux, http.MethodDelete, "/api/v1/config/"+key, "test-token", "")

	want := map[string]bool{"config.set": false, "config.reset": false}
	for _, e := range audit.entries {
		if _, ok := want[e.Action]; !ok {
			continue
		}
		if e.ResourceID != key || e.ActorID == "" || e.ActorID == "anonymous" || e.Outcome != AuditOutcomeSuccess {
			t.Errorf("audit row %+v lacks actor/key/success", e)
		}
		want[e.Action] = true
	}
	for action, seen := range want {
		if !seen {
			t.Errorf("no %s audit row", action)
		}
	}
}
