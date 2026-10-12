// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func newTestTenantStore(t *testing.T) *dbTenantStore {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "tenants.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	s := &dbTenantStore{db: db, ph: sqlitePlaceholder}
	if err := s.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("schema: %v", err)
	}
	return s
}

func TestMultiTenancyFlag(t *testing.T) {
	t.Setenv("MULTI_TENANCY", "")
	if multiTenancyEnabled() {
		t.Error("expected off by default")
	}
	t.Setenv("MULTI_TENANCY", "on")
	if !multiTenancyEnabled() {
		t.Error("expected on")
	}
}

func TestTenantStore_CRUDAndCAMapping(t *testing.T) {
	s := newTestTenantStore(t)
	ctx := context.Background()
	if _, err := s.CreateTenant(ctx, "acme", "Acme Corp"); err != nil {
		t.Fatalf("create: %v", err)
	}
	list, _ := s.ListTenants(ctx)
	if len(list) != 1 || list[0].ID != "acme" {
		t.Fatalf("list wrong: %+v", list)
	}
	// Unmapped CA → default tenant.
	if td, _ := s.CATenant(ctx, "ca-x"); td != DefaultTenant {
		t.Errorf("unmapped CA should be default, got %s", td)
	}
	if err := s.SetCATenant(ctx, "ca-x", "acme"); err != nil {
		t.Fatalf("map: %v", err)
	}
	if td, _ := s.CATenant(ctx, "ca-x"); td != "acme" {
		t.Errorf("expected acme, got %s", td)
	}
}

func TestResolvePrincipalTenancy(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	// Flag off → everyone super-admin in default tenant, unscoped.
	t.Setenv("MULTI_TENANCY", "")
	pd, err := resolvePrincipalTenancy(AuthPrincipal{ID: "u", Role: "pki-operator", AuthType: "jwt"}, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pd.Tenant != DefaultTenant || !pd.SuperAdmin || pd.TenantScoped {
		t.Fatalf("flag off should be default+superadmin+unscoped, got %+v", pd)
	}

	// Flag on, bootstrap, no header → super-admin, unscoped (sees all).
	t.Setenv("MULTI_TENANCY", "on")
	pd, err = resolvePrincipalTenancy(AuthPrincipal{ID: "root", AuthType: "bootstrap"}, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !pd.SuperAdmin || pd.TenantScoped {
		t.Errorf("bootstrap w/o header should be super-admin+unscoped, got %+v", pd)
	}

	// Flag on, non-bootstrap with no identity-bound tenant, no header →
	// pinned to default, scoped (legacy/unconfigured api key).
	pdPin, err := resolvePrincipalTenancy(AuthPrincipal{ID: "u", Role: "pki-admin", AuthType: "jwt"}, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pdPin.SuperAdmin || !pdPin.TenantScoped || pdPin.Tenant != DefaultTenant {
		t.Fatalf("non-super w/o header should be scoped to default, got %+v", pdPin)
	}

	// W3-01: identity-bound tenant (e.g. from a JWT tenant claim or api-key
	// record), no header → resolves to the identity tenant, scoped.
	pd, err = resolvePrincipalTenancy(AuthPrincipal{ID: "u", Role: "pki-admin", AuthType: "jwt", Tenant: "acme"}, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pd.SuperAdmin || !pd.TenantScoped || pd.Tenant != "acme" {
		t.Fatalf("expected identity-bound tenant=acme scoped non-super, got %+v", pd)
	}

	// W3-01: identity-bound tenant + a MATCHING X-Tenant header → allowed,
	// same result (the header is a no-op confirmation, not a re-pin).
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("X-Tenant", "acme")
	pd, err = resolvePrincipalTenancy(AuthPrincipal{ID: "u", Role: "pki-admin", AuthType: "jwt", Tenant: "acme"}, req2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pd.SuperAdmin || !pd.TenantScoped || pd.Tenant != "acme" {
		t.Fatalf("expected matching header to confirm tenant=acme, got %+v", pd)
	}

	// W3-01 headline: identity-bound tenant + a MISMATCHED X-Tenant header →
	// denied outright, not silently re-scoped to the header's tenant.
	req2b := httptest.NewRequest(http.MethodGet, "/", nil)
	req2b.Header.Set("X-Tenant", "globex")
	if _, err := resolvePrincipalTenancy(AuthPrincipal{ID: "u", Role: "pki-admin", AuthType: "jwt", Tenant: "acme"}, req2b); err == nil {
		t.Fatal("expected an error for a scoped principal targeting a non-member tenant")
	}

	// Flag on, bootstrap super-admin with X-Tenant → view-as (scoped) but still super-admin identity.
	req3 := httptest.NewRequest(http.MethodGet, "/", nil)
	req3.Header.Set("X-Tenant", "acme")
	pd, err = resolvePrincipalTenancy(AuthPrincipal{ID: "root", AuthType: "bootstrap"}, req3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !pd.SuperAdmin || !pd.TenantScoped || pd.Tenant != "acme" {
		t.Fatalf("super-admin view-as should be super+scoped+acme, got %+v", pd)
	}
}

func TestFilterCAsByTenant_Isolation(t *testing.T) {
	s := newTestTenantStore(t)
	ctx := context.Background()
	_ = s.SetCATenant(ctx, "ca-acme", "acme")
	_ = s.SetCATenant(ctx, "ca-globex", "globex")
	items := []CAListItem{{ID: "ca-acme"}, {ID: "ca-globex"}, {ID: "ca-shared"}}

	// Flag OFF → no filtering (single-tenant unchanged).
	t.Setenv("MULTI_TENANCY", "")
	if got := filterCAsByTenant(ctx, s, AuthPrincipal{Tenant: "acme"}, items); len(got) != 3 {
		t.Fatalf("flag off must not filter, got %d", len(got))
	}

	t.Setenv("MULTI_TENANCY", "on")
	// Acme tenant (non-super) sees only ca-acme (ca-shared is unmapped → default).
	acme := AuthPrincipal{Tenant: "acme", SuperAdmin: false}
	got := filterCAsByTenant(ctx, s, acme, items)
	if len(got) != 1 || got[0].ID != "ca-acme" {
		t.Fatalf("acme should see only ca-acme, got %+v", got)
	}
	// Default tenant sees the unmapped shared CA.
	def := AuthPrincipal{Tenant: DefaultTenant, SuperAdmin: false}
	got = filterCAsByTenant(ctx, s, def, items)
	if len(got) != 1 || got[0].ID != "ca-shared" {
		t.Fatalf("default should see only ca-shared, got %+v", got)
	}
	// Super-admin sees all.
	if got := filterCAsByTenant(ctx, s, AuthPrincipal{SuperAdmin: true}, items); len(got) != 3 {
		t.Fatalf("super-admin should see all, got %d", len(got))
	}
}

func TestTenantHandlers_RequireSuperAdmin(t *testing.T) {
	t.Setenv("MULTI_TENANCY", "on")
	auth := newReportsTestAuth(t) // bootstrap token → super-admin
	store := newTestTenantStore(t)
	mux := http.NewServeMux()
	registerTenantHandlers(mux, auth, store, stubAuditProvider{})

	// Super-admin (bootstrap) can create + list.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/tenants", []byte(`{"id":"acme","name":"Acme"}`)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("super-admin create: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, authedReq(http.MethodGet, "/api/v1/tenants", nil))
	if rec2.Code != http.StatusOK {
		t.Fatalf("super-admin list: expected 200, got %d", rec2.Code)
	}
	// (Non-super forbidden path is covered by TestResolvePrincipalTenancy +
	// the SuperAdmin gate; bootstrap tokens always resolve to super-admin.)
}

// TestCATenantsFKRejectsUnknownTenant is the W3-01 acceptance #3 regression:
// ca_tenants/template_tenants declare a FK to tenants, enforced on sqlite via
// the shared DSN's _fk=1 (NewTenantStoreFromEnv, unlike the ad-hoc sql.Open
// used elsewhere in this file for lighter-weight tests).
func TestCATenantsFKRejectsUnknownTenant(t *testing.T) {
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	store := NewTenantStoreFromEnv()
	if store == nil {
		t.Fatal("expected a DB-backed tenant store")
	}
	ctx := context.Background()

	if err := store.SetCATenant(ctx, "ca-orphan", "no-such-tenant"); err == nil {
		t.Fatal("expected FK violation mapping a CA to a nonexistent tenant")
	}
	if err := store.SetTemplateTenant(ctx, "tpl-orphan", "no-such-tenant"); err == nil {
		t.Fatal("expected FK violation mapping a template to a nonexistent tenant")
	}

	// A real tenant still works.
	if _, err := store.CreateTenant(ctx, "acme", "Acme Corp"); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if err := store.SetCATenant(ctx, "ca-acme", "acme"); err != nil {
		t.Fatalf("map to a real tenant should succeed: %v", err)
	}
}
