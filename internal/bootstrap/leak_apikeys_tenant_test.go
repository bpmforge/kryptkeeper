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

// doLeakJSON sends an authenticated request with an explicit body. The tenant
// header is optional; tenant principals are pinned to their identity tenant.
func doLeakJSON(mux *http.ServeMux, method, path, token, tenant, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	if tenant != "" {
		req.Header.Set("X-Tenant", tenant)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func apiKeyKids(t *testing.T, rec *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	var out struct {
		Data []struct {
			Kid  string `json:"kid"`
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode api-keys: %v", err)
	}
	m := map[string]string{}
	for _, d := range out.Data {
		m[d.Name] = d.Kid
	}
	return m
}

// TestLeakL01_APIKeyMintForcedToCallerTenant: a tenant admin must not mint keys
// into another tenant, default, an unknown tenant, or the bootstrap role.
func TestLeakL01_APIKeyMintForcedToCallerTenant(t *testing.T) {
	mux, acme, _ := setupTenantWritePathTest(t)
	for _, tc := range []struct{ name, body string }{
		{"other tenant", `{"name":"x","role":"pki-admin","tenant":"globex"}`},
		{"default tenant", `{"name":"x","role":"pki-admin","tenant":"default"}`},
		{"unknown tenant", `{"name":"x","role":"pki-admin","tenant":"nonexistent"}`},
		{"bootstrap role", `{"name":"x","role":"bootstrap"}`},
	} {
		rec := doLeakJSON(mux, http.MethodPost, "/api/v1/api-keys", acme, "", tc.body)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: want 403, got %d %s", tc.name, rec.Code, rec.Body.String())
		}
	}
	// Omitted tenant is bound to the caller's tenant, never default.
	rec := doLeakJSON(mux, http.MethodPost, "/api/v1/api-keys", acme, "", `{"name":"own","principal_id":"svc-own","role":"pki-admin"}`)
	if rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), `"tenant":"acme"`) {
		t.Fatalf("own-tenant mint: %d %s", rec.Code, rec.Body.String())
	}
	// Super-admin may target an existing tenant but not an unknown one.
	rec = doLeakJSON(mux, http.MethodPost, "/api/v1/api-keys", "root-token", "", `{"name":"g","principal_id":"svc-g","role":"pki-admin","tenant":"globex"}`)
	if rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), `"tenant":"globex"`) {
		t.Fatalf("super-admin mint into globex: %d %s", rec.Code, rec.Body.String())
	}
	rec = doLeakJSON(mux, http.MethodPost, "/api/v1/api-keys", "root-token", "", `{"name":"u","role":"pki-admin","tenant":"nonexistent"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("super-admin mint into unknown tenant: want 400, got %d", rec.Code)
	}
}

// TestLeakL02_APIKeyListAndDeleteScopedToTenant: list hides other tenants' keys
// and DELETE refuses them.
func TestLeakL02_APIKeyListAndDeleteScopedToTenant(t *testing.T) {
	mux, acme, _ := setupTenantWritePathTest(t)
	rec := doLeakJSON(mux, http.MethodGet, "/api/v1/api-keys", acme, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d", rec.Code)
	}
	kids := apiKeyKids(t, rec)
	if _, ok := kids["acme-svc"]; !ok {
		t.Fatalf("acme should see own key: %v", kids)
	}
	if _, ok := kids["globex-svc"]; ok {
		t.Fatalf("acme sees globex key: %v", kids)
	}
	all := apiKeyKids(t, doLeakJSON(mux, http.MethodGet, "/api/v1/api-keys", "root-token", "", ""))
	gx := all["globex-svc"]
	if gx == "" {
		t.Fatalf("super-admin should see globex key: %v", all)
	}
	rec = doLeakJSON(mux, http.MethodDelete, "/api/v1/api-keys/"+gx, acme, "", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant delete: want 404, got %d", rec.Code)
	}
	if _, ok := apiKeyKids(t, doLeakJSON(mux, http.MethodGet, "/api/v1/api-keys", "root-token", "", ""))["globex-svc"]; !ok {
		t.Fatal("globex key was revoked/removed by acme")
	}
	rec = doLeakJSON(mux, http.MethodDelete, "/api/v1/api-keys/"+kids["acme-svc"], acme, "", "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("own-tenant delete: want 204, got %d", rec.Code)
	}
}
