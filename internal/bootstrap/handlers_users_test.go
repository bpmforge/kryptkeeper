// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type stubUserProvider struct {
	users []UserRecord
}

func (p *stubUserProvider) ListUsers(_ context.Context) ([]UserRecord, error) {
	return p.users, nil
}

func (p *stubUserProvider) InviteUser(_ context.Context, email string, role string) (UserRecord, error) {
	u := UserRecord{ID: "new-1", Email: email, Role: role, Status: "active", CreatedAt: "2026-01-01T00:00:00Z"}
	p.users = append(p.users, u)
	return u, nil
}

func (p *stubUserProvider) UpdateUser(_ context.Context, id string, role string, status string) (UserRecord, error) {
	for i, u := range p.users {
		if u.ID == id {
			if role != "" {
				p.users[i].Role = role
			}
			if status != "" {
				p.users[i].Status = status
			}
			return p.users[i], nil
		}
	}
	return UserRecord{}, nil
}

func (p *stubUserProvider) DeactivateUser(_ context.Context, id string) error {
	for i, u := range p.users {
		if u.ID == id {
			p.users[i].Status = "deactivated"
		}
	}
	return nil
}

func newUserTestMux(t *testing.T, provider UserProvider) *http.ServeMux {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	registerUserHandlers(mux, auth, provider, nil, stubAuditProvider{})
	return mux
}

func TestUserHandlerListReturnsUsers(t *testing.T) {
	provider := &stubUserProvider{users: []UserRecord{
		{ID: "u1", Email: "admin@example.com", Role: "pki-admin", Status: "active", CreatedAt: "2026-01-01T00:00:00Z"},
	}}
	mux := newUserTestMux(t, provider)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			Items []UserRecord `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Data.Items) != 1 || resp.Data.Items[0].Email != "admin@example.com" {
		t.Errorf("unexpected items: %+v", resp.Data.Items)
	}
}

// RC1 LOW: the account directory is not readable by non-admin principals.
func TestUserHandlerListForbiddenForLowRoles(t *testing.T) {
	auth := &Authenticator{
		config: authValidatorConfig{
			mode: "bootstrap", bootstrapToken: "test-token", loginEnabled: true,
			loginSigning: "signing-secret", loginTTL: 5 * time.Minute, refreshTTL: 10 * time.Minute,
		},
		refreshSessions: map[string]refreshSession{},
	}
	mux := http.NewServeMux()
	registerUserHandlers(mux, auth, &stubUserProvider{users: []UserRecord{{ID: "u1", Email: "a@example.com"}}}, nil, stubAuditProvider{})
	for _, role := range []string{"pki-viewer", "pki-operator", "mcp-agent"} {
		tok, _, _, _, err := auth.mintSessionForUser("u-"+role, role, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: expected 403, got %d", role, rec.Code)
		}
	}
}

func TestUserHandlerListRequiresAuth(t *testing.T) {
	mux := newUserTestMux(t, &stubUserProvider{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestUserHandlerInvite(t *testing.T) {
	mux := newUserTestMux(t, &stubUserProvider{})

	body, _ := json.Marshal(map[string]string{"email": "new@example.com", "role": "pki-operator"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/invite", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data UserRecord `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Data.Email != "new@example.com" {
		t.Errorf("unexpected email %q", resp.Data.Email)
	}
}

func TestUserHandlerInviteMissingEmail(t *testing.T) {
	mux := newUserTestMux(t, &stubUserProvider{})

	body, _ := json.Marshal(map[string]string{"role": "pki-operator"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/invite", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestUserHandlerPatch(t *testing.T) {
	provider := &stubUserProvider{users: []UserRecord{
		{ID: "u1", Email: "user@example.com", Role: "pki-viewer", Status: "active", CreatedAt: "2026-01-01T00:00:00Z"},
	}}
	mux := newUserTestMux(t, provider)

	body, _ := json.Marshal(map[string]string{"role": "pki-admin"})
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/users/u1", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestUserHandlerDeactivate(t *testing.T) {
	provider := &stubUserProvider{users: []UserRecord{
		{ID: "u1", Email: "user@example.com", Role: "pki-viewer", Status: "active", CreatedAt: "2026-01-01T00:00:00Z"},
	}}
	mux := newUserTestMux(t, provider)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/u1", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestAdminConsoleDeactivateViaProductionWiringRevokesOrdinaryRoute exercises
// the wiring RegisterHandlers actually uses in production (handlers.go ->
// NewAuthenticatorFromEnv + RegisterHandlers), not registerUserHandlers
// called directly with a hand-injected shared provider like every other test
// in this file. handlers.go used to mint its own NewUserProviderFromEnv()
// instance for registerUserHandlers, independent of auth.userProvider -- in
// the default (non-DB) in-memory configuration, an admin-console DELETE
// /api/v1/users/{id} would deactivate a user in a store the deprovision
// enforcement check (AuthenticatePrincipalDetails) never saw, so a
// hand-injected test asserting DeactivateUser's effect would pass while doing
// nothing for a real deployment. This is the one test that exercises that
// exact seam (W6-10, same class of bug as W6-02's SCIM fix in
// handlers_auth_test.go).
func TestAdminConsoleDeactivateViaProductionWiringRevokesOrdinaryRoute(t *testing.T) {
	// S-40 made the database the default provider. This test targets the
	// file-mode wiring class specifically (W6-02/W6-10: disconnected
	// in-memory provider instances), so it asks for that mode by name
	// instead of relying on it being the default.
	t.Setenv("APP_USER_PROVIDER", "file")

	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_AUTH_LOGIN_SIGNING_SECRET", "signing-secret")
	// authenticateBootstrap (auth_bootstrap.go) only redeems a login-session
	// JWT when loginEnabled or oidcLoginEnabled is set alongside loginSigning
	// -- mirrors TestSCIMDeprovisionViaProductionWiringRevokesOrdinaryRoute's
	// setup (handlers_auth_test.go) for the same reason.
	t.Setenv("APP_OIDC_LOGIN_ENABLED", "true")

	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	RegisterHandlers(mux, auth, stubCertSummaryProvider{}, stubAuditProvider{}, stubCAProvider{}, stubTemplateProvider{}, NewFileCertificateProviderFromEnv(), NewProtocolProviderFromEnv(), NewDiscoveryProviderFromEnv(), NewNotificationProviderFromEnv(), NewDashboardActionProviderFromEnv(), nil)

	created, err := auth.userProvider.InviteUser(context.Background(), "kim@example.com", "pki-operator")
	if err != nil {
		t.Fatalf("seed user via auth.userProvider: %v", err)
	}

	now := time.Now()
	accessToken, _, _, _, err := auth.mintSessionForUser(created.ID, "pki-operator", now)
	if err != nil {
		t.Fatalf("mintSessionForUser: %v", err)
	}
	if _, err := auth.AuthenticatePrincipalDetails(bearerRequest(accessToken), now); err != nil {
		t.Fatalf("expected the session to authenticate before admin-console deactivation: %v", err)
	}

	deleteReq := httptest.NewRequest(http.MethodDelete, "/api/v1/users/"+created.ID, nil)
	deleteReq.Header.Set("Authorization", "Bearer test-token")
	deleteRec := httptest.NewRecorder()
	mux.ServeHTTP(deleteRec, deleteReq)
	if deleteRec.Code != http.StatusNoContent {
		t.Fatalf("admin-console deactivate: expected 204, got %d (%s)", deleteRec.Code, deleteRec.Body.String())
	}

	if _, err := auth.AuthenticatePrincipalDetails(bearerRequest(accessToken), now); err == nil {
		t.Fatal("expected a principal deactivated through the admin-console endpoint, reached via production RegisterHandlers wiring, to be rejected on an ordinary protected route")
	}
}
