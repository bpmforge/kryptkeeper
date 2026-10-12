// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestRegisterAuthHandlers_WrapperStillWorks proves the public
// registerAuthHandlers (the signature handlers.go depends on, unchanged)
// still wires a working mux after being split into a thin wrapper around
// registerAuthHandlersWithUsers.
func TestRegisterAuthHandlers_WrapperStillWorks(t *testing.T) {
	auth := &Authenticator{
		config: authValidatorConfig{
			mode:           "bootstrap",
			bootstrapToken: "test-bootstrap-token",
		},
		refreshSessions:  map[string]refreshSession{},
		rateLimitBuckets: map[string][]time.Time{},
	}
	mux := http.NewServeMux()
	registerAuthHandlers(mux, auth, stubAuditProvider{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/authz-check", nil)
	req.Header.Set("Authorization", "Bearer test-bootstrap-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected the bootstrap token to authenticate through the public wrapper, got %d (%s)", rec.Code, rec.Body.String())
	}
}

// TestSCIMDeprovisionViaProductionWiringRevokesOrdinaryRoute exercises the
// wiring registerAuthHandlers actually uses in production (handlers.go ->
// NewAuthenticatorFromEnv + registerAuthHandlers), not the *WithUsers form
// tests elsewhere hand-inject a shared provider into. registerAuthHandlers
// used to mint its own NewUserProviderFromEnv() instance independent of
// auth.userProvider -- in the default (non-DB) in-memory configuration, a
// SCIM deprovision write would land on a store the deprovision-enforcement
// read (AuthenticatePrincipalDetails) never saw, so the fix from
// TestDeprovisionedPrincipalRejectedOnOrdinaryRoute (auth_test.go) would
// pass unit tests while doing nothing for a real deployment. This is the one
// test that exercises that exact seam.
func TestSCIMDeprovisionViaProductionWiringRevokesOrdinaryRoute(t *testing.T) {
	// S-40 made the database the default provider. This test targets the
	// file-mode wiring class specifically (W6-02/W6-10: disconnected
	// in-memory provider instances), so it asks for that mode by name
	// instead of relying on it being the default.
	t.Setenv("APP_USER_PROVIDER", "file")

	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_AUTH_LOGIN_SIGNING_SECRET", "signing-secret")
	t.Setenv("APP_OIDC_LOGIN_ENABLED", "true")
	t.Setenv("APP_SCIM_TOKEN", testSCIMBearerToken)
	t.Setenv("APP_SCIM_DEFAULT_ROLE", "pki-viewer")

	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	registerAuthHandlers(mux, auth, stubAuditProvider{})

	createRec := httptest.NewRecorder()
	mux.ServeHTTP(createRec, scimAuthedRequest(http.MethodPost, "/scim/v2/Users", `{"userName":"kim@example.com","active":true}`))
	if createRec.Code != http.StatusCreated {
		t.Fatalf("SCIM create user: expected 201, got %d (%s)", createRec.Code, createRec.Body.String())
	}
	var created scimUserResource
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode SCIM create response: %v", err)
	}

	now := time.Now()
	accessToken, _, _, _, err := auth.mintSessionForUser(created.ID, "pki-operator", now)
	if err != nil {
		t.Fatalf("mintSessionForUser: %v", err)
	}
	if _, err := auth.AuthenticatePrincipalDetails(bearerRequest(accessToken), now); err != nil {
		t.Fatalf("expected the session to authenticate before SCIM deprovisioning: %v", err)
	}

	deactivateRec := httptest.NewRecorder()
	mux.ServeHTTP(deactivateRec, scimAuthedRequest(http.MethodDelete, "/scim/v2/Users/"+created.ID, ""))
	if deactivateRec.Code != http.StatusNoContent {
		t.Fatalf("SCIM deactivate user: expected 204, got %d (%s)", deactivateRec.Code, deactivateRec.Body.String())
	}

	if _, err := auth.AuthenticatePrincipalDetails(bearerRequest(accessToken), now); err == nil {
		t.Fatal("expected a SCIM-deprovisioned principal to be rejected through the production registerAuthHandlers wiring, not just when a test hand-injects a shared UserProvider")
	}
}

func TestPrincipalIsDeprovisioned(t *testing.T) {
	provider := &fileUserProvider{users: []UserRecord{
		{ID: "user-1", Email: "alice@example.com", Status: "active"},
		{ID: "user-2", Email: "bob@example.com", Status: "deactivated"},
	}}

	deprovisioned, err := principalIsDeprovisioned(context.Background(), provider, "user-1")
	if err != nil || deprovisioned {
		t.Fatalf("expected user-1 (active) to not be deprovisioned, got %v, err=%v", deprovisioned, err)
	}

	deprovisioned, err = principalIsDeprovisioned(context.Background(), provider, "user-2")
	if err != nil || !deprovisioned {
		t.Fatalf("expected user-2 (deactivated) to be deprovisioned, got %v, err=%v", deprovisioned, err)
	}
}

// TestPrincipalIsDeprovisioned_UnknownPrincipalUnaffected proves principals
// with no matching UserRecord (local admin, API keys, service accounts) are
// left alone by the deprovision gate.
func TestPrincipalIsDeprovisioned_UnknownPrincipalUnaffected(t *testing.T) {
	provider := &fileUserProvider{}

	deprovisioned, err := principalIsDeprovisioned(context.Background(), provider, "bootstrap")
	if err != nil || deprovisioned {
		t.Fatalf("expected an unknown principal to be unaffected, got %v, err=%v", deprovisioned, err)
	}
}

func TestPrincipalIsDeprovisioned_EmptyPrincipal(t *testing.T) {
	provider := &fileUserProvider{}
	deprovisioned, err := principalIsDeprovisioned(context.Background(), provider, "")
	if err != nil || deprovisioned {
		t.Fatalf("expected an empty principal id to be unaffected, got %v, err=%v", deprovisioned, err)
	}
}
