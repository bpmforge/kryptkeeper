// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestLeakL18_UsersAreTenantScoped(t *testing.T) {
	setupTenantWritePathTest(t) // env, tenants, and activeTenantStore
	auth := NewAuthenticatorFromEnv()
	_, acme, _ := auth.CreateAPIKey("acme-a", "acme-a", "pki-admin", []string{"*"}, "", "acme", time.Now())
	_, globex, _ := auth.CreateAPIKey("globex-a", "globex-a", "pki-admin", []string{"*"}, "", "globex", time.Now())
	users := NewFileUserProvider()
	mux := http.NewServeMux()
	registerUserHandlers(mux, auth, users, nil, stubAuditProvider{})

	// A super-admin seeds one account per tenant.
	if code, body := tenantReqBody(mux, http.MethodPost, "/api/v1/users/invite", "root-token", "", `{"email":"g@globex.example","tenant":"globex"}`); code != http.StatusCreated {
		t.Fatalf("super-admin invite: %d %s", code, body)
	}
	var created struct {
		Data UserRecord `json:"data"`
	}
	code, body := tenantReqBody(mux, http.MethodPost, "/api/v1/users/invite", acme, "acme", `{"email":"a@acme.example","role":"pki-admin"}`)
	if code != http.StatusCreated {
		t.Fatalf("acme invite: %d %s", code, body)
	}
	_ = json.Unmarshal([]byte(body), &created)
	if created.Data.Tenant != "acme" {
		t.Fatalf("invite must stamp caller tenant, got %q", created.Data.Tenant)
	}
	if code, _ := tenantReqBody(mux, http.MethodPost, "/api/v1/users/invite", acme, "acme", `{"email":"x@y.example","tenant":"globex"}`); code != http.StatusForbidden {
		t.Fatalf("cross-tenant invite want 403, got %d", code)
	}

	list := func(token, tenant string) []UserRecord {
		code, body := tenantReqBody(mux, http.MethodGet, "/api/v1/users", token, tenant, "")
		if code != http.StatusOK {
			t.Fatalf("list: %d %s", code, body)
		}
		var resp struct {
			Data struct {
				Items []UserRecord `json:"items"`
			} `json:"data"`
		}
		_ = json.Unmarshal([]byte(body), &resp)
		return resp.Data.Items
	}
	if got := list(acme, "acme"); len(got) != 1 || got[0].Email != "a@acme.example" {
		t.Fatalf("acme must see only its user, got %+v", got)
	}
	if got := list("root-token", ""); len(got) != 2 {
		t.Fatalf("super-admin sees all, got %+v", got)
	}

	if code, _ := tenantReqBody(mux, http.MethodDelete, "/api/v1/users/"+created.Data.ID, globex, "globex", ""); code != http.StatusNotFound {
		t.Fatalf("cross-tenant delete want 404, got %d", code)
	}
	if code, _ := tenantReqBody(mux, http.MethodPatch, "/api/v1/users/"+created.Data.ID, globex, "globex", `{"role":"viewer"}`); code != http.StatusNotFound {
		t.Fatalf("cross-tenant patch want 404, got %d", code)
	}
	if code, _ := tenantReqBody(mux, http.MethodDelete, "/api/v1/users/"+created.Data.ID, acme, "acme", ""); code != http.StatusNoContent {
		t.Fatalf("own-tenant delete want 204, got %d", code)
	}
}

func TestLeakL18_DBProviderPersistsTenant(t *testing.T) {
	p := newFreshUserDBProvider(t)
	ctx := context.Background()
	u, err := p.InviteUserInTenant(ctx, "t@acme.example", "pki-viewer", "acme")
	if err != nil || u.Tenant != "acme" {
		t.Fatalf("invite: %+v %v", u, err)
	}
	d, _ := p.InviteUser(ctx, "d@example.com", "pki-viewer")
	if d.Tenant != "" {
		t.Fatalf("default invite stores empty tenant, got %q", d.Tenant)
	}
	all, err := p.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range all {
		if r.Email == "t@acme.example" && r.Tenant != "acme" {
			t.Fatalf("tenant not persisted: %+v", r)
		}
	}
}
