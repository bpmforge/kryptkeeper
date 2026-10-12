// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// newSessionAuthenticator builds an Authenticator configured for local login
// (mode "bootstrap", the auth mode the raw bootstrap token also uses) with
// the given resolved role for the local user.
func newSessionAuthenticator(role string) *Authenticator {
	return &Authenticator{
		config: authValidatorConfig{
			mode:           "bootstrap",
			bootstrapToken: "root-token",
			loginEnabled:   true,
			loginSigning:   "signing-secret",
			loginTTL:       5 * time.Minute,
			refreshTTL:     10 * time.Minute,
			loginPepper:    "pepper",
			loginUser: loginCredential{
				Email:        "user@example.com",
				PasswordHash: apiKeyVerifier("pass", "pepper"),
				Role:         role,
				Subject:      "team-1",
				Active:       true,
			},
		},
		refreshSessions: map[string]refreshSession{},
	}
}

func bearerRequest(token string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

// TestSessionAuthenticatesAsResolvedNonAdminRole is S-34 acceptance #2: a
// session minted for a principal whose resolved role is NOT pki-admin must
// authenticate on subsequent requests AS THAT ROLE — not pki-admin, not with
// wildcard scopes, and not as SuperAdmin.
func TestSessionAuthenticatesAsResolvedNonAdminRole(t *testing.T) {
	t.Setenv("MULTI_TENANCY", "on")
	auth := newSessionAuthenticator("pki-viewer")
	now := time.Now().UTC()

	accessToken, _, _, _, principal, err := auth.Login("user@example.com", "pass", now)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if principal.Role != "pki-viewer" {
		t.Fatalf("login response principal role = %q, want pki-viewer", principal.Role)
	}

	pd, err := auth.AuthenticatePrincipalDetails(bearerRequest(accessToken), now)
	if err != nil {
		t.Fatalf("authenticate session: %v", err)
	}
	if pd.Role != "pki-viewer" {
		t.Fatalf("session resolved role = %q, want pki-viewer", pd.Role)
	}
	if hasScope(pd.Scopes, "*") {
		t.Fatalf("session got wildcard scope: %+v", pd.Scopes)
	}
	if pd.SuperAdmin {
		t.Fatalf("non-admin session resolved as SuperAdmin: %+v", pd)
	}
}

// TestRawBootstrapTokenUnchanged is S-34 acceptance #3: the raw bootstrap
// token keeps its existing pki-admin + ["*"] + SuperAdmin behaviour.
func TestRawBootstrapTokenUnchanged(t *testing.T) {
	t.Setenv("MULTI_TENANCY", "on")
	auth := newSessionAuthenticator("pki-viewer")
	now := time.Now().UTC()

	pd, err := auth.AuthenticatePrincipalDetails(bearerRequest("root-token"), now)
	if err != nil {
		t.Fatalf("authenticate raw bootstrap token: %v", err)
	}
	if pd.Role != "pki-admin" {
		t.Fatalf("raw bootstrap token role = %q, want pki-admin", pd.Role)
	}
	if !hasScope(pd.Scopes, "*") {
		t.Fatalf("raw bootstrap token missing wildcard scope: %+v", pd.Scopes)
	}
	if !pd.SuperAdmin {
		t.Fatalf("raw bootstrap token not resolved as SuperAdmin: %+v", pd)
	}
}

// TestPkiViewerSessionDeniedCanManageDiscovery is S-34 acceptance #5: a
// pki-viewer session is denied an action that canManageX gates on pki-admin,
// while the same gate still allows the raw bootstrap (pki-admin) principal.
func TestPkiViewerSessionDeniedCanManageDiscovery(t *testing.T) {
	auth := newSessionAuthenticator("pki-viewer")
	now := time.Now().UTC()

	accessToken, _, _, _, _, err := auth.Login("user@example.com", "pass", now)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	viewerPD, err := auth.AuthenticatePrincipalDetails(bearerRequest(accessToken), now)
	if err != nil {
		t.Fatalf("authenticate session: %v", err)
	}
	if canManageDiscovery(viewerPD) {
		t.Fatalf("pki-viewer session was allowed to manage discovery: %+v", viewerPD)
	}

	adminPD, err := auth.AuthenticatePrincipalDetails(bearerRequest("root-token"), now)
	if err != nil {
		t.Fatalf("authenticate bootstrap token: %v", err)
	}
	if !canManageDiscovery(adminPD) {
		t.Fatalf("pki-admin bootstrap principal was denied managing discovery: %+v", adminPD)
	}
}

// TestNonAdminSessionTenancyNotSuperAdmin is S-34 acceptance #6:
// resolvePrincipalTenancy must not resolve a non-admin session as SuperAdmin,
// covered as its own assertion distinct from the role/scope checks above.
func TestNonAdminSessionTenancyNotSuperAdmin(t *testing.T) {
	t.Setenv("MULTI_TENANCY", "on")
	auth := newSessionAuthenticator("pki-viewer")
	now := time.Now().UTC()

	accessToken, _, _, _, _, err := auth.Login("user@example.com", "pass", now)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	pd, err := auth.AuthenticatePrincipalDetails(bearerRequest(accessToken), now)
	if err != nil {
		t.Fatalf("authenticate session: %v", err)
	}
	if pd.SuperAdmin {
		t.Fatalf("resolvePrincipalTenancy resolved a pki-viewer session as SuperAdmin: %+v", pd)
	}
}

// TestDeprovisionedPrincipalRejectedOnOrdinaryRoute proves acceptance #4
// ("deprovisioning a user revokes their access") end to end, not just at
// /api/v1/authz-check's own separate check (handlers_auth.go). authenticatePrincipal
// / AuthenticatePrincipalDetails is the shared path every protected handler
// resolves its caller through, so this exercises that path directly, the way
// an ordinary protected route (not authz-check) would.
func TestDeprovisionedPrincipalRejectedOnOrdinaryRoute(t *testing.T) {
	userProvider := &fileUserProvider{users: []UserRecord{
		{ID: "user-1", Email: "ivan@example.com", Role: "pki-operator", Status: "active"},
	}}
	auth := &Authenticator{
		config: authValidatorConfig{
			mode:             "bootstrap",
			oidcLoginEnabled: true,
			loginSigning:     "signing-secret",
			loginTTL:         5 * time.Minute,
			refreshTTL:       10 * time.Minute,
		},
		refreshSessions: map[string]refreshSession{},
		userProvider:    userProvider,
	}
	now := time.Now().UTC()

	accessToken, _, _, _, err := auth.mintSessionForUser("user-1", "pki-operator", now)
	if err != nil {
		t.Fatalf("mintSessionForUser: %v", err)
	}

	pd, err := auth.AuthenticatePrincipalDetails(bearerRequest(accessToken), now)
	if err != nil {
		t.Fatalf("expected the session to authenticate before deprovisioning: %v", err)
	}
	if pd.ID != "user-1" {
		t.Fatalf("pd.ID = %q, want user-1", pd.ID)
	}

	if err := userProvider.DeactivateUser(context.Background(), "user-1"); err != nil {
		t.Fatalf("DeactivateUser: %v", err)
	}

	if _, err := auth.AuthenticatePrincipalDetails(bearerRequest(accessToken), now); err == nil {
		t.Fatal("expected a deprovisioned principal's pre-existing session to be rejected on an ordinary protected route, not just at authz-check")
	}
}

// TestSessionJWTWithoutRoleClaimRejected proves a loginSigning-signed JWT
// carrying no "role" claim — e.g. one minted before this change, or a
// hand-crafted token — is rejected rather than defaulted to pki-admin. That
// default is exactly the escalation S-34 fixes, so a missing claim must fail
// closed.
func TestSessionJWTWithoutRoleClaimRejected(t *testing.T) {
	auth := newSessionAuthenticator("pki-viewer")
	now := time.Now().UTC()

	roleless := signHS256JWT(t, "signing-secret", map[string]any{
		"sub": "team-1", "exp": float64(now.Add(time.Hour).Unix()),
	})

	if _, err := auth.AuthenticatePrincipalDetails(bearerRequest(roleless), now); err == nil {
		t.Fatal("expected a session JWT with no role claim to be rejected")
	}
}

// TestAuthenticatePrincipalDetails_SSOConfigStoreOverrideAppliesOnNextUse is
// the W8-13 acceptance #2 test for the SSO/OIDC bearer-token consumer: a DB
// override written through the real config store must change the SAME
// Authenticator's AuthenticatePrincipalDetails behaviour on its NEXT call,
// with no reconstruction. It also proves acceptance #3's bound in passing:
// a write made mid-TTL-window is not observed until the window elapses.
//
// Sabotage-checked: temporarily hardcoded ssoBearerConfigSnapshot to always
// return a.config's bootstrap default (ignoring a.configStore) and confirmed
// this test goes red, then reverted.
func TestAuthenticatePrincipalDetails_SSOConfigStoreOverrideAppliesOnNextUse(t *testing.T) {
	store := newFreshConfigStore(t, []byte("test-passphrase"))
	ctx := context.Background()

	priv := generateTestRSAKey(t)
	jwks := buildTestJWKS(t, "kid-1", &priv.PublicKey)
	now := time.Now().UTC()
	token := signTestRS256JWT(t, priv, "kid-1", map[string]any{
		"sub": "svc-1",
		"iss": "https://db-issuer.example.com",
		"aud": "db-audience",
		"exp": float64(now.Add(time.Hour).Unix()),
	})

	clock := now
	auth := &Authenticator{
		config: authValidatorConfig{
			mode:         "oidc",
			oidcIssuer:   "https://env-issuer.example.com",
			oidcAudience: "env-audience",
			oidcJWKSJSON: jwks,
			tenantClaim:  "tenant",
		},
		configStore:  store,
		ssoConfigNow: func() time.Time { return clock },
	}

	if _, err := auth.AuthenticatePrincipalDetails(bearerRequest(token), now); err == nil {
		t.Fatal("expected a token issued for the DB issuer/audience to be rejected before any override is written (bootstrap default is the env issuer)")
	}

	if err := store.Set(ctx, "sso.oidc_issuer", "https://db-issuer.example.com", "test-operator"); err != nil {
		t.Fatalf("write issuer override: %v", err)
	}
	if err := store.Set(ctx, "sso.oidc_audience", "db-audience", "test-operator"); err != nil {
		t.Fatalf("write audience override: %v", err)
	}

	// Still within the TTL window opened by the first call above -- the
	// override must NOT be observed yet (bounded read, acceptance #3).
	if _, err := auth.AuthenticatePrincipalDetails(bearerRequest(token), now); err == nil {
		t.Fatal("expected the override to be invisible within the same TTL window")
	}

	clock = clock.Add(2 * ssoBearerConfigTTL) // advance past the TTL

	// Same Authenticator instance -- no reconstruction.
	if _, err := auth.AuthenticatePrincipalDetails(bearerRequest(token), now); err != nil {
		t.Fatalf("expected the DB override issuer/audience to validate the token on next use once the TTL elapses, got %v", err)
	}
}

// TestAuthenticatePrincipalDetails_SSOConfigBoundedReadsWithinTTL proves
// acceptance #3's bound directly: repeated authenticated requests within one
// TTL window must issue exactly one config-store read each for issuer,
// audience, and JWKS -- not one per request. AuthenticatePrincipalDetails
// runs on every request including unauthenticated ones, so this is exactly
// the "unauthenticated-request-triggered unbounded query" acceptance #3
// warns against.
func TestAuthenticatePrincipalDetails_SSOConfigBoundedReadsWithinTTL(t *testing.T) {
	inner := newFreshConfigStore(t, []byte("test-passphrase"))
	counting := &countingConfigStore{ConfigStore: inner}

	priv := generateTestRSAKey(t)
	jwks := buildTestJWKS(t, "kid-1", &priv.PublicKey)
	now := time.Now().UTC()
	token := signTestRS256JWT(t, priv, "kid-1", map[string]any{
		"sub": "svc-1",
		"iss": "https://env-issuer.example.com",
		"aud": "env-audience",
		"exp": float64(now.Add(time.Hour).Unix()),
	})

	clock := now
	auth := &Authenticator{
		config: authValidatorConfig{
			mode:         "oidc",
			oidcIssuer:   "https://env-issuer.example.com",
			oidcAudience: "env-audience",
			oidcJWKSJSON: jwks,
			tenantClaim:  "tenant",
		},
		configStore:  counting,
		ssoConfigNow: func() time.Time { return clock },
	}

	for i := 0; i < 5; i++ {
		if _, err := auth.AuthenticatePrincipalDetails(bearerRequest(token), now); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	// Get is called once for the issuer key and once for the audience key on
	// the single cache refresh -- 2 total, not 2 per request.
	if got := atomic.LoadInt32(&counting.gets); got != 2 {
		t.Fatalf("expected exactly 2 config store Get calls across 5 requests within one TTL window, got %d", got)
	}
}

// TestAuthenticatePrincipalDetails_SSOConfigStoreNilFallsBackToEnvDefault
// guards the pre-W8-13 behavior: a nil configStore (store unavailable) must
// not panic and bearer-token OIDC validation must keep using the
// env-derived bootstrap default in config exactly as before.
func TestAuthenticatePrincipalDetails_SSOConfigStoreNilFallsBackToEnvDefault(t *testing.T) {
	priv := generateTestRSAKey(t)
	jwks := buildTestJWKS(t, "kid-1", &priv.PublicKey)
	now := time.Now().UTC()
	token := signTestRS256JWT(t, priv, "kid-1", map[string]any{
		"sub": "svc-1",
		"iss": "https://env-issuer.example.com",
		"aud": "env-audience",
		"exp": float64(now.Add(time.Hour).Unix()),
	})

	auth := &Authenticator{
		config: authValidatorConfig{
			mode:         "oidc",
			oidcIssuer:   "https://env-issuer.example.com",
			oidcAudience: "env-audience",
			oidcJWKSJSON: jwks,
			tenantClaim:  "tenant",
		},
		// configStore intentionally left nil.
	}

	if _, err := auth.AuthenticatePrincipalDetails(bearerRequest(token), now); err != nil {
		t.Fatalf("expected env-default issuer/audience to validate with a nil config store, got %v", err)
	}
}
