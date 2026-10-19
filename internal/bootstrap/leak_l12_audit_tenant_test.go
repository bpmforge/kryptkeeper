// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func leakAuditSetup(t *testing.T) (h http.Handler, prov AuditProvider, acmeToken, globexToken string) {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "root-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32-chars-minimum!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	t.Setenv("MULTI_TENANCY", "on")
	auth := NewAuthenticatorFromEnv()
	_, acmeToken, _ = auth.CreateAPIKey("acme-adm", "acme-adm", "pki-admin", []string{"*"}, "", "acme", time.Now())
	_, globexToken, _ = auth.CreateAPIKey("globex-adm", "globex-adm", "pki-admin", []string{"*"}, "", "globex", time.Now())
	p, err := openFileAuditProvider(filepath.Join(t.TempDir(), "audit.json"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerAuditHandlers(mux, auth, NewCustomRoleStoreFromEnv(), p, auditNameSources{})
	return withAuditTenant(mux), p, acmeToken, globexToken
}

func leakAuditGet(h http.Handler, path, token, tenant string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if tenant != "" {
		req.Header.Set("X-Tenant", tenant)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestLeakL12_AuditStampedFromPrincipalAndFiltered: rows carry the resolved
// principal's tenant (not the raw header), anonymous probes are filed under
// the default tenant, and GET /audit only returns the caller's tenant.
func TestLeakL12_AuditStampedFromPrincipalAndFiltered(t *testing.T) {
	h, prov, acmeTok, globexTok := leakAuditSetup(t)

	if rec := leakAuditGet(h, "/api/v1/audit", globexTok, "globex"); rec.Code != http.StatusOK {
		t.Fatalf("globex list: %d %s", rec.Code, rec.Body.String())
	}
	// Anonymous request forging X-Tenant: globex must not be filed under globex.
	if rec := leakAuditGet(h, "/api/v1/audit", "", "globex"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anon list: %d", rec.Code)
	}

	all, err := prov.ListEntries(context.Background(), AuditListQuery{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	var sawGlobex, sawAnonDefault bool
	for _, e := range all.Entries {
		switch {
		case e.ActorID == "globex-adm" && e.Tenant == "globex":
			sawGlobex = true
		case e.ActorID == "anonymous" && e.Tenant == DefaultTenant:
			sawAnonDefault = true
		case e.ActorID == "anonymous":
			t.Fatalf("anonymous row stamped %q from forged header", e.Tenant)
		}
	}
	if !sawGlobex || !sawAnonDefault {
		t.Fatalf("expected globex-stamped and default-stamped anon rows: %+v", all.Entries)
	}

	rec := leakAuditGet(h, "/api/v1/audit?limit=100", acmeTok, "acme")
	if rec.Code != http.StatusOK {
		t.Fatalf("acme list: %d %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Data []struct {
			ActorID string `json:"actor_id"`
			Tenant  string `json:"tenant"`
		} `json:"data"`
		Meta struct {
			Total int `json:"total"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	for _, e := range body.Data {
		if e.Tenant != "acme" {
			t.Fatalf("acme saw %q row (actor %s)", e.Tenant, e.ActorID)
		}
	}
	if body.Meta.Total != len(body.Data) {
		t.Fatalf("meta.total %d != %d rows", body.Meta.Total, len(body.Data))
	}
}
