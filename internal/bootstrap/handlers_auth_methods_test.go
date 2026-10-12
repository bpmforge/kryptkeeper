// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The login page renders sign-in buttons from this unauthenticated probe —
// before it existed, an OIDC-only deployment had no way to sign in from
// the console at all.
func TestAuthMethodsProbeIsUnauthenticatedAndHonest(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_AUTH_LOGIN_ENABLED", "true")
	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	registerAuthMethodsHandler(mux, auth)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/methods", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 without credentials, got %d", rec.Code)
	}
	var resp struct {
		Data struct {
			Password bool `json:"password"`
			OIDC     bool `json:"oidc"`
			SAML     bool `json:"saml"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Data.Password {
		t.Error("password login enabled via env but reported off")
	}
	if resp.Data.OIDC || resp.Data.SAML {
		t.Error("SSO not configured but reported on")
	}
	// Nothing beyond booleans may leak.
	for _, secret := range []string{"issuer", "client", "endpoint", "http"} {
		if json.Valid(rec.Body.Bytes()) && strings.Contains(strings.ToLower(rec.Body.String()), secret) {
			t.Errorf("response leaks configuration detail %q: %s", secret, rec.Body.String())
		}
	}
}
