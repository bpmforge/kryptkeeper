// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"testing"
	"time"
)

// TestSSOOnlySessionAuthenticates is W6-02's fix for a real SSO-only
// deployment defect: authenticateBootstrap used to gate ALL session-JWT
// acceptance on cfg.loginEnabled (the local-password toggle), so a
// deployment with APP_AUTH_LOGIN_ENABLED unset and OIDC login on would mint
// a valid, correctly-signed session cookie at the OIDC callback and then
// 401 "unauthorized" on the very next request -- login worked, nothing
// after it did. mintSessionForUser (auth_oidc_login.go) mints the identical
// HS256 JWT Login() does, so authenticateBootstrap must accept it whenever
// either login path is enabled, not only the local one.
func TestSSOOnlySessionAuthenticates(t *testing.T) {
	auth := &Authenticator{
		config: authValidatorConfig{
			mode:             "bootstrap",
			bootstrapToken:   "root-token",
			loginEnabled:     false,
			oidcLoginEnabled: true,
			loginSigning:     "signing-secret",
			loginTTL:         5 * time.Minute,
			refreshTTL:       10 * time.Minute,
		},
		refreshSessions: map[string]refreshSession{},
	}
	now := time.Now().UTC()

	accessToken, _, _, _, err := auth.mintSessionForUser("sso-user-1", "pki-viewer", now)
	if err != nil {
		t.Fatalf("mintSessionForUser: %v", err)
	}

	pd, err := auth.AuthenticatePrincipalDetails(bearerRequest(accessToken), now)
	if err != nil {
		t.Fatalf("SSO-only session was rejected by authenticateBootstrap: %v", err)
	}
	if pd.ID != "sso-user-1" {
		t.Fatalf("resolved principal ID = %q, want sso-user-1", pd.ID)
	}
	if pd.Role != "pki-viewer" {
		t.Fatalf("resolved role = %q, want pki-viewer", pd.Role)
	}
	if pd.AuthType != "local" {
		t.Fatalf("resolved auth type = %q, want local (matching Login()'s own stamp)", pd.AuthType)
	}
}

// TestLocalOnlySessionStillAuthenticates guards the other half of the fix:
// a deployment with OIDC login off must not regress -- a local-login
// session still authenticates when oidcLoginEnabled is false.
func TestLocalOnlySessionStillAuthenticates(t *testing.T) {
	auth := newSessionAuthenticator("pki-viewer")
	now := time.Now().UTC()

	accessToken, _, _, _, _, err := auth.Login("user@example.com", "pass", now)
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	pd, err := auth.AuthenticatePrincipalDetails(bearerRequest(accessToken), now)
	if err != nil {
		t.Fatalf("local-login session was rejected: %v", err)
	}
	if pd.Role != "pki-viewer" {
		t.Fatalf("resolved role = %q, want pki-viewer", pd.Role)
	}
}

// TestSAMLOnlySessionAuthenticates is W6-13's fix for the third instance of
// the defect W6-02 already fixed once for OIDC: authenticateBootstrap's
// login-session-JWT gate checked only cfg.loginEnabled || cfg.oidcLoginEnabled,
// so a SAML-only deployment (APP_SAML_LOGIN_ENABLED=true, password login and
// OIDC login both off) minted a valid session at the SAML ACS endpoint
// (auth_saml.go) and then rejected it on the very next request.
// mintSessionForUser mints the identical HS256 JWT regardless of which login
// flow called it, so authenticateBootstrap must accept it whenever ANY
// session-issuing login flow is enabled -- proven here independently of the
// full SAML assertion round trip (see auth_saml_test.go for that).
func TestSAMLOnlySessionAuthenticates(t *testing.T) {
	auth := &Authenticator{
		config: authValidatorConfig{
			mode:             "bootstrap",
			bootstrapToken:   "root-token",
			loginEnabled:     false,
			oidcLoginEnabled: false,
			samlLoginEnabled: true,
			loginSigning:     "signing-secret",
			loginTTL:         5 * time.Minute,
			refreshTTL:       10 * time.Minute,
		},
		refreshSessions: map[string]refreshSession{},
	}
	now := time.Now().UTC()

	accessToken, _, _, _, err := auth.mintSessionForUser("saml-user-1", "pki-viewer", now)
	if err != nil {
		t.Fatalf("mintSessionForUser: %v", err)
	}

	pd, err := auth.AuthenticatePrincipalDetails(bearerRequest(accessToken), now)
	if err != nil {
		t.Fatalf("SAML-only session was rejected by authenticateBootstrap: %v", err)
	}
	if pd.ID != "saml-user-1" {
		t.Fatalf("resolved principal ID = %q, want saml-user-1", pd.ID)
	}
	if pd.Role != "pki-viewer" {
		t.Fatalf("resolved role = %q, want pki-viewer", pd.Role)
	}
	if pd.AuthType != "local" {
		t.Fatalf("resolved auth type = %q, want local (matching Login()'s own stamp)", pd.AuthType)
	}
}

// TestNeitherLoginPathEnabledSessionRejected proves the gate still fails
// closed when neither login path is on: a session JWT must not authenticate
// against a deployment that never should have been able to mint one.
func TestNeitherLoginPathEnabledSessionRejected(t *testing.T) {
	signer := &Authenticator{
		config: authValidatorConfig{
			mode:             "bootstrap",
			bootstrapToken:   "root-token",
			loginEnabled:     false,
			oidcLoginEnabled: true,
			loginSigning:     "signing-secret",
			loginTTL:         5 * time.Minute,
			refreshTTL:       10 * time.Minute,
		},
		refreshSessions: map[string]refreshSession{},
	}
	now := time.Now().UTC()
	accessToken, _, _, _, err := signer.mintSessionForUser("sso-user-1", "pki-viewer", now)
	if err != nil {
		t.Fatalf("mintSessionForUser: %v", err)
	}

	locked := &Authenticator{
		config: authValidatorConfig{
			mode:             "bootstrap",
			loginEnabled:     false,
			oidcLoginEnabled: false,
			loginSigning:     "signing-secret",
		},
		refreshSessions: map[string]refreshSession{},
	}
	if _, err := locked.AuthenticatePrincipalDetails(bearerRequest(accessToken), now); err == nil {
		t.Fatalf("session authenticated against a deployment with both login paths disabled")
	}
}
