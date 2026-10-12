// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAuthenticatePrincipalAcceptsAPIKeyToken(t *testing.T) {
	secret := "secret-123"
	auth := &Authenticator{
		config: authValidatorConfig{
			mode:              "bootstrap",
			apiKeyAuthEnabled: true,
			apiKeyPepper:      "pepper",
			apiKeys: map[string]apiKeyRecord{
				"kid1": {
					Kid:            "kid1",
					SecretVerifier: apiKeyVerifier(secret, "pepper"),
					PrincipalID:    "team-1",
					Role:           "service-account",
					Active:         true,
				},
			},
		},
		refreshSessions: map[string]refreshSession{},
	}

	req := httptest.NewRequest("GET", "/api/v1/authz-check", nil)
	req.Header.Set("Authorization", "Bearer kk_kid1_"+secret)

	principal, err := auth.AuthenticatePrincipal(req, time.Now())
	if err != nil {
		t.Fatalf("expected api key auth success, got error: %v", err)
	}
	if principal != "team-1" {
		t.Fatalf("expected principal team-1, got %q", principal)
	}
}

func TestLoginAndRefreshRotateToken(t *testing.T) {
	now := time.Now().UTC()
	auth := &Authenticator{
		config: authValidatorConfig{
			loginEnabled: true,
			loginSigning: "signing-secret",
			loginTTL:     5 * time.Minute,
			refreshTTL:   10 * time.Minute,
			loginPepper:  "pepper",
			loginUser: loginCredential{
				Email:        "admin@example.com",
				PasswordHash: apiKeyVerifier("pass", "pepper"),
				Role:         "pki-admin",
				Subject:      "team-1",
				Active:       true,
			},
		},
		refreshSessions: map[string]refreshSession{},
	}

	accessToken, _, refreshToken, _, principal, err := auth.Login("admin@example.com", "pass", now)
	if err != nil {
		t.Fatalf("expected login success, got error: %v", err)
	}
	if accessToken == "" || refreshToken == "" {
		t.Fatal("expected non-empty access and refresh tokens")
	}
	if principal.ID != "team-1" {
		t.Fatalf("expected principal team-1, got %q", principal.ID)
	}

	newAccess, _, newRefresh, _, err := auth.Refresh(refreshToken, now.Add(1*time.Minute))
	if err != nil {
		t.Fatalf("expected refresh success, got error: %v", err)
	}
	if newAccess == "" || newRefresh == "" {
		t.Fatal("expected non-empty rotated tokens")
	}
	if newRefresh == refreshToken {
		t.Fatal("expected refresh token rotation")
	}

	if _, _, _, _, err := auth.Refresh(refreshToken, now.Add(2*time.Minute)); err == nil {
		t.Fatal("expected old refresh token to be invalid after rotation")
	}
}

// TestRefreshRejectsDeprovisionedPrincipal is acceptance #4's other half: a
// deprovisioned principal must not be able to mint a fresh access token off a
// still-valid refresh token at /api/v1/auth/refresh, the same way an ordinary
// protected route rejects their existing access token
// (TestDeprovisionedPrincipalRejectedOnOrdinaryRoute, auth_test.go).
func TestRefreshRejectsDeprovisionedPrincipal(t *testing.T) {
	userProvider := &fileUserProvider{users: []UserRecord{
		{ID: "user-1", Email: "judy@example.com", Role: "pki-operator", Status: "active"},
	}}
	auth := &Authenticator{
		config: authValidatorConfig{
			mode:         "bootstrap",
			loginSigning: "signing-secret",
			loginTTL:     5 * time.Minute,
			refreshTTL:   10 * time.Minute,
		},
		refreshSessions: map[string]refreshSession{},
		userProvider:    userProvider,
	}
	now := time.Now().UTC()

	_, _, refreshToken, _, err := auth.mintSessionForUser("user-1", "pki-operator", now)
	if err != nil {
		t.Fatalf("mintSessionForUser: %v", err)
	}

	if err := userProvider.DeactivateUser(context.Background(), "user-1"); err != nil {
		t.Fatalf("DeactivateUser: %v", err)
	}

	if _, _, _, _, err := auth.Refresh(refreshToken, now.Add(1*time.Minute)); err == nil {
		t.Fatal("expected refresh to fail for a deprovisioned principal")
	}
}

// TestRefreshPreservesNonAdminRole is S-34 acceptance #4: Refresh() re-mints
// via the same mintHS256JWT path Login() uses, so a session must not
// silently escalate on its first refresh. Covers login -> refresh ->
// authorize as a non-admin role.
func TestRefreshPreservesNonAdminRole(t *testing.T) {
	now := time.Now().UTC()
	auth := &Authenticator{
		config: authValidatorConfig{
			mode:           "bootstrap",
			bootstrapToken: "root-token",
			loginEnabled:   true,
			loginSigning:   "signing-secret",
			loginTTL:       5 * time.Minute,
			refreshTTL:     10 * time.Minute,
			loginPepper:    "pepper",
			loginUser: loginCredential{
				Email:        "viewer@example.com",
				PasswordHash: apiKeyVerifier("pass", "pepper"),
				Role:         "pki-viewer",
				Subject:      "team-2",
				Active:       true,
			},
		},
		refreshSessions: map[string]refreshSession{},
	}

	_, _, refreshToken, _, principal, err := auth.Login("viewer@example.com", "pass", now)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if principal.Role != "pki-viewer" {
		t.Fatalf("login principal role = %q, want pki-viewer", principal.Role)
	}

	newAccess, _, _, _, err := auth.Refresh(refreshToken, now.Add(1*time.Minute))
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}

	pd, err := auth.AuthenticatePrincipalDetails(bearerRequest(newAccess), now.Add(1*time.Minute))
	if err != nil {
		t.Fatalf("authenticate refreshed session: %v", err)
	}
	if pd.Role != "pki-viewer" {
		t.Fatalf("refreshed session escalated: role = %q, want pki-viewer", pd.Role)
	}
	if hasScope(pd.Scopes, "*") {
		t.Fatalf("refreshed session escalated to wildcard scope: %+v", pd.Scopes)
	}
}
