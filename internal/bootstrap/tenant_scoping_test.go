// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

// W2: every resource type stays inside its tenant. Each sub-test proves tenant
// A cannot see tenant B's resource with the flag ON, and that flag-OFF /
// super-admin see everything.

func TestFilterCertificatesByTenant(t *testing.T) {
	s := newTestTenantStore(t)
	ctx := context.Background()
	_ = s.SetCATenant(ctx, "ca-acme", "acme")
	_ = s.SetCATenant(ctx, "ca-globex", "globex")
	items := []CertificateItem{
		{FingerprintSHA256: "c1", CAID: "ca-acme"},
		{FingerprintSHA256: "c2", CAID: "ca-globex"},
		{FingerprintSHA256: "c3", CAID: "ca-unmapped"}, // → default tenant
	}

	t.Setenv("MULTI_TENANCY", "")
	if got := filterCertificatesByTenant(ctx, s, AuthPrincipal{Tenant: "acme"}, items); len(got) != 3 {
		t.Fatalf("flag off must not filter, got %d", len(got))
	}

	t.Setenv("MULTI_TENANCY", "on")
	acme := filterCertificatesByTenant(ctx, s, AuthPrincipal{Tenant: "acme"}, items)
	if len(acme) != 1 || acme[0].CAID != "ca-acme" {
		t.Fatalf("acme should see only its cert, got %+v", acme)
	}
	def := filterCertificatesByTenant(ctx, s, AuthPrincipal{Tenant: DefaultTenant}, items)
	if len(def) != 1 || def[0].FingerprintSHA256 != "c3" {
		t.Fatalf("default should see only the unmapped-CA cert, got %+v", def)
	}
	if all := filterCertificatesByTenant(ctx, s, AuthPrincipal{SuperAdmin: true}, items); len(all) != 3 {
		t.Fatalf("super-admin should see all, got %d", len(all))
	}
}

func TestFilterApprovalsByTenant(t *testing.T) {
	s := newTestTenantStore(t)
	ctx := context.Background()
	_ = s.SetCATenant(ctx, "ca-acme", "acme")
	items := []ApprovalRequest{
		{ID: "a1", CAID: "ca-acme"},
		{ID: "a2", CAID: "ca-globex"}, // unmapped → default
	}
	t.Setenv("MULTI_TENANCY", "on")
	acme := filterApprovalsByTenant(ctx, s, AuthPrincipal{Tenant: "acme"}, items)
	if len(acme) != 1 || acme[0].ID != "a1" {
		t.Fatalf("acme should see only a1, got %+v", acme)
	}
	globex := filterApprovalsByTenant(ctx, s, AuthPrincipal{Tenant: "globex"}, items)
	if len(globex) != 0 {
		t.Fatalf("globex maps to no approval (a2 is default), got %+v", globex)
	}
}

func TestFilterTemplatesByTenant(t *testing.T) {
	s := newTestTenantStore(t)
	ctx := context.Background()
	_ = s.SetTemplateTenant(ctx, "tpl-acme", "acme")
	items := []TemplateItem{
		{ID: "tpl-acme"},
		{ID: "tpl-shared"}, // unmapped → default (shared catalog)
	}
	t.Setenv("MULTI_TENANCY", "on")
	acme := filterTemplatesByTenant(ctx, s, AuthPrincipal{Tenant: "acme"}, items)
	if len(acme) != 1 || acme[0].ID != "tpl-acme" {
		t.Fatalf("acme should see only its template, got %+v", acme)
	}
	def := filterTemplatesByTenant(ctx, s, AuthPrincipal{Tenant: DefaultTenant}, items)
	if len(def) != 1 || def[0].ID != "tpl-shared" {
		t.Fatalf("default should see only the shared template, got %+v", def)
	}
	if all := filterTemplatesByTenant(ctx, s, AuthPrincipal{SuperAdmin: true}, items); len(all) != 2 {
		t.Fatalf("super-admin should see all, got %d", len(all))
	}
}

func TestFilterPendingActionsByTenant(t *testing.T) {
	items := []PendingAction{
		{ID: "act-1", Tenant: "acme"},
		{ID: "act-2", Tenant: "globex"},
		{ID: "act-3", Tenant: ""}, // legacy row → default
	}
	t.Setenv("MULTI_TENANCY", "")
	if got := filterPendingActionsByTenant(AuthPrincipal{Tenant: "acme"}, items); len(got) != 3 {
		t.Fatalf("flag off must not filter, got %d", len(got))
	}
	t.Setenv("MULTI_TENANCY", "on")
	acme := filterPendingActionsByTenant(AuthPrincipal{Tenant: "acme"}, items)
	if len(acme) != 1 || acme[0].ID != "act-1" {
		t.Fatalf("acme should see only act-1, got %+v", acme)
	}
	def := filterPendingActionsByTenant(AuthPrincipal{Tenant: DefaultTenant}, items)
	if len(def) != 1 || def[0].ID != "act-3" {
		t.Fatalf("default should see only the legacy act-3, got %+v", def)
	}
	if all := filterPendingActionsByTenant(AuthPrincipal{SuperAdmin: true}, items); len(all) != 3 {
		t.Fatalf("super-admin should see all, got %d", len(all))
	}
}

// A super-admin who opts into a tenant ("view-as") IS filtered to it, while an
// unscoped super-admin still sees everything.
func TestSuperAdminViewAsScoping(t *testing.T) {
	s := newTestTenantStore(t)
	ctx := context.Background()
	_ = s.SetCATenant(ctx, "ca-acme", "acme")
	items := []CAListItem{{ID: "ca-acme"}, {ID: "ca-globex"}}
	t.Setenv("MULTI_TENANCY", "on")

	unscoped := AuthPrincipal{SuperAdmin: true, TenantScoped: false}
	if got := filterCAsByTenant(ctx, s, unscoped, items); len(got) != 2 {
		t.Fatalf("unscoped super-admin should see all, got %d", len(got))
	}
	viewAs := AuthPrincipal{SuperAdmin: true, TenantScoped: true, Tenant: "acme"}
	got := filterCAsByTenant(ctx, s, viewAs, items)
	if len(got) != 1 || got[0].ID != "ca-acme" {
		t.Fatalf("view-as acme should see only ca-acme, got %+v", got)
	}
}

// PendingAction tenant survives a round-trip through the store.
func TestPendingActionStore_PersistsTenant(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "pa.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	store := &dbPendingActionStore{db: db, ph: sqlitePlaceholder}
	if err := store.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("schema: %v", err)
	}
	created, err := store.Create(context.Background(), PendingAction{
		ActionType: "revoke",
		Params:     json.RawMessage(`{"fingerprint":"abc"}`),
		ProposedBy: "agent-1",
		Tenant:     "acme",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.Tenant != "acme" {
		t.Fatalf("created tenant = %q, want acme", created.Tenant)
	}
	got, ok, err := store.Get(context.Background(), created.ID)
	if err != nil || !ok {
		t.Fatalf("get: ok=%v err=%v", ok, err)
	}
	if got.Tenant != "acme" {
		t.Fatalf("persisted tenant = %q, want acme", got.Tenant)
	}
	// Default applied when proposer has no tenant (legacy / single-tenant).
	created2, err := store.Create(context.Background(), PendingAction{ActionType: "revoke", ProposedBy: "x"})
	if err != nil {
		t.Fatalf("create2: %v", err)
	}
	if created2.Tenant != DefaultTenant {
		t.Fatalf("empty tenant should default, got %q", created2.Tenant)
	}
}
