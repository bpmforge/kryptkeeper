// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

// TestScopedPrincipalDeniedOnTenantMismatch is the W3-01 headline regression:
// a scoped (non-super-admin) principal's tenant is identity-bound (from its
// api-key record), not header-driven — sending an X-Tenant naming any OTHER
// tenant must be denied, not silently re-scoped to it.
func TestScopedPrincipalDeniedOnTenantMismatch(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "root-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32-chars-minimum!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	t.Setenv("MULTI_TENANCY", "on")

	t.Setenv("APP_AUDIT_FILE", filepath.Join(t.TempDir(), "audit.json"))

	auth := NewAuthenticatorFromEnv()
	_, acmeToken, err := auth.CreateAPIKey("acme-svc", "svc-principal", "pki-admin", []string{"*"}, "", "acme", time.Now())
	if err != nil {
		t.Fatalf("create acme api key: %v", err)
	}

	mux := http.NewServeMux()
	RegisterHandlers(mux, auth, stubCertSummaryForAudit{}, mustFileAudit(t), stubCAProviderForAudit{}, stubTemplateProviderForAudit{}, NewFileCertificateProviderFromEnv(), NewProtocolProviderFromEnv(), NewDiscoveryProviderFromEnv(), NewNotificationProviderFromEnv(), NewDashboardActionProviderFromEnv(), nil)

	// Own tenant: allowed.
	ownReq := httptest.NewRequest(http.MethodGet, "/api/v1/protected/ping", nil)
	ownReq.Header.Set("Authorization", "Bearer "+acmeToken)
	ownReq.Header.Set("X-Tenant", "acme")
	ownRec := httptest.NewRecorder()
	mux.ServeHTTP(ownRec, ownReq)
	if ownRec.Code != http.StatusOK {
		t.Fatalf("own-tenant request: expected 200, got %d: %s", ownRec.Code, ownRec.Body.String())
	}

	// Someone else's tenant: denied outright (not silently re-scoped).
	mismatchReq := httptest.NewRequest(http.MethodGet, "/api/v1/protected/ping", nil)
	mismatchReq.Header.Set("Authorization", "Bearer "+acmeToken)
	mismatchReq.Header.Set("X-Tenant", "globex")
	mismatchRec := httptest.NewRecorder()
	mux.ServeHTTP(mismatchRec, mismatchReq)
	if mismatchRec.Code != http.StatusUnauthorized {
		t.Fatalf("cross-tenant mismatch: expected 401, got %d: %s", mismatchRec.Code, mismatchRec.Body.String())
	}

	// No header at all: falls back to the identity-bound tenant, allowed.
	noHeaderReq := httptest.NewRequest(http.MethodGet, "/api/v1/protected/ping", nil)
	noHeaderReq.Header.Set("Authorization", "Bearer "+acmeToken)
	noHeaderRec := httptest.NewRecorder()
	mux.ServeHTTP(noHeaderRec, noHeaderReq)
	if noHeaderRec.Code != http.StatusOK {
		t.Fatalf("no-header request: expected 200, got %d: %s", noHeaderRec.Code, noHeaderRec.Body.String())
	}
}

// TestSuperAdminViewAsStillAllowed proves the super-admin "view-as" path
// (bootstrap token) is unaffected by W3-01's identity-binding: it can still
// select any tenant via X-Tenant with no membership check.
func TestSuperAdminViewAsStillAllowed(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "root-token")
	t.Setenv("MULTI_TENANCY", "on")

	t.Setenv("APP_AUDIT_FILE", filepath.Join(t.TempDir(), "audit.json"))

	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	RegisterHandlers(mux, auth, stubCertSummaryForAudit{}, mustFileAudit(t), stubCAProviderForAudit{}, stubTemplateProviderForAudit{}, NewFileCertificateProviderFromEnv(), NewProtocolProviderFromEnv(), NewDiscoveryProviderFromEnv(), NewNotificationProviderFromEnv(), NewDashboardActionProviderFromEnv(), nil)

	for _, tenant := range []string{"acme", "globex", "some-other-tenant"} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/protected/ping", nil)
		req.Header.Set("Authorization", "Bearer root-token")
		req.Header.Set("X-Tenant", tenant)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("super-admin view-as %q: expected 200, got %d: %s", tenant, rec.Code, rec.Body.String())
		}
	}
}

// TestJWTPrincipalTenantClaimEndToEndDeniedOnMismatch closes the seam
// TestValidateHS256JWTExtractsTenantClaim doesn't reach: a JWT-mode
// principal's tenant claim actually flows through authenticatePrincipal ->
// resolvePrincipalTenancy end-to-end, including the deny-on-mismatch path.
// If a future change dropped the Tenant field on the AuthPrincipal{} built
// in the "jwt" case, every principal would silently become DefaultTenant —
// this test catches that class of regression.
func TestJWTPrincipalTenantClaimEndToEndDeniedOnMismatch(t *testing.T) {
	t.Setenv("AUTH_MODE", "jwt")
	t.Setenv("APP_JWT_HS256_SECRET", "test-jwt-secret")
	t.Setenv("APP_AUTH_UNMAPPED_ROLE", "read-only") // tenant claim test, not role mapping
	t.Setenv("MULTI_TENANCY", "on")

	auth := NewAuthenticatorFromEnv()
	now := time.Now()
	token := signHS256JWT(t, "test-jwt-secret", map[string]any{
		"sub": "svc-jwt", "exp": float64(now.Add(time.Hour).Unix()), "tenant": "acme",
	})

	own := httptest.NewRequest(http.MethodGet, "/", nil)
	own.Header.Set("Authorization", "Bearer "+token)
	own.Header.Set("X-Tenant", "acme")
	pd, err := auth.AuthenticatePrincipalDetails(own, now)
	if err != nil {
		t.Fatalf("own-tenant: unexpected error: %v", err)
	}
	if pd.Tenant != "acme" || pd.SuperAdmin {
		t.Fatalf("expected identity-bound tenant=acme, non-super, got %+v", pd)
	}

	mismatch := httptest.NewRequest(http.MethodGet, "/", nil)
	mismatch.Header.Set("Authorization", "Bearer "+token)
	mismatch.Header.Set("X-Tenant", "globex")
	if _, err := auth.AuthenticatePrincipalDetails(mismatch, now); err == nil {
		t.Fatal("expected a JWT principal targeting a non-member tenant to be denied")
	}
}
