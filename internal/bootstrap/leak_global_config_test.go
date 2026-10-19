// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"net/http"
	"testing"
	"time"
)

// TestLeakL08_GlobalConfigRequiresSuperAdmin: a tenant admin must not read or
// rewrite instance-wide configuration; the super-admin still can.
func TestLeakL08_GlobalConfigRequiresSuperAdmin(t *testing.T) {
	mux, acme, _ := setupTenantWritePathTest(t)
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/config", ""},
		{http.MethodPut, "/api/v1/config/sso.oidc_jwks_json", `{"value":"{}"}`},
		{http.MethodDelete, "/api/v1/config/sso.oidc_jwks_json", ""},
		{http.MethodPost, "/api/v1/delivery-plugins", `{}`},
		{http.MethodPost, "/api/v1/adsync/templates", `{}`},
	} {
		rec := doLeakJSON(mux, tc.method, tc.path, acme, "", tc.body)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s as tenant admin: want 403, got %d %s", tc.method, tc.path, rec.Code, rec.Body.String())
		}
	}
	// Super-admin is not refused by the tenancy gate (any other status is fine).
	if rec := doLeakJSON(mux, http.MethodPut, "/api/v1/config/sso.oidc_jwks_json", "root-token", "", `{"value":"{}"}`); rec.Code == http.StatusForbidden {
		t.Errorf("super-admin config PUT refused: %s", rec.Body.String())
	}
}

// TestLeakL08_SCEPChallengesRequireSuperAdmin covers the instance-wide SCEP CA.
func TestLeakL08_SCEPChallengesRequireSuperAdmin(t *testing.T) {
	mux, auth, _, _ := newSCEPChallengeMux(t)
	t.Setenv("MULTI_TENANCY", "on")
	_, acme, err := auth.CreateAPIKey("acme-svc", "svc-acme", "pki-admin", []string{"*"}, "", "acme", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if rec := doLeakJSON(mux, http.MethodGet, "/api/v1/scep/challenges", acme, "", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("tenant admin SCEP list: want 403, got %d", rec.Code)
	}
	if rec := doLeakJSON(mux, http.MethodGet, "/api/v1/scep/challenges", "test-token", "", ""); rec.Code != http.StatusOK {
		t.Fatalf("super-admin SCEP list: want 200, got %d %s", rec.Code, rec.Body.String())
	}
}
