// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"database/sql"
	"errors"
	"net/http"
	"testing"
)

// RC2-N-02: the env login admin is reserved by email as well as subject, and a
// user-store outage refuses key creation instead of letting it through.
func TestAPIKeyPrincipalIDReservedForLoginAdminEmail(t *testing.T) {
	e := newEgressEnv(t, "false")
	e.auth.userProvider = &fileUserProvider{users: []UserRecord{{ID: "u1", Email: "u1@example.com", Role: "viewer", Status: "active"}}}
	e.auth.config.loginEnabled = true
	e.auth.config.loginUser = loginCredential{Email: "Probe@Example.com", Subject: "probe-admin", Role: "pki-admin", Active: true}
	for _, id := range []string{"probe-admin", "probe@example.com", " PROBE@example.com "} {
		rec := e.post(t, e.alice, "/api/v1/api-keys", map[string]any{"name": "x", "principal_id": id, "role": "pki-admin", "scopes": []string{"*"}})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("principal_id=%q: want 400, got %d: %s", id, rec.Code, rec.Body.String())
		}
	}
	rec := e.post(t, e.alice, "/api/v1/api-keys", map[string]any{"name": "x", "principal_id": "svc-deploy", "role": "pki-admin", "scopes": []string{"*"}})
	if rec.Code != http.StatusCreated {
		t.Fatalf("an unreserved service name must still mint: %d %s", rec.Code, rec.Body.String())
	}
}

func TestAPIKeyCreateFailsClosedWhenUserStoreErrors(t *testing.T) {
	e := newEgressEnv(t, "false")
	flaky := &flakyUserProvider{UserProvider: &fileUserProvider{}, fail: true}
	e.auth.userProvider = flaky
	rec := e.post(t, e.alice, "/api/v1/api-keys", map[string]any{"name": "x", "principal_id": "svc-deploy", "role": "pki-admin", "scopes": []string{"*"}})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("user-store error: want 503, got %d: %s", rec.Code, rec.Body.String())
	}
	flaky.setFail(false)
	rec = e.post(t, e.alice, "/api/v1/api-keys", map[string]any{"name": "x", "principal_id": "svc-deploy", "role": "pki-admin", "scopes": []string{"*"}})
	if rec.Code != http.StatusCreated {
		t.Fatalf("store back: want 201, got %d: %s", rec.Code, rec.Body.String())
	}
}

// A default install whose hub never ran the core migrations has no users
// table. That is "no user store", not an outage: key creation must work, and
// the built-in identities stay reserved.
func TestAPIKeyCreateWithUnprovisionedDefaultUserStore(t *testing.T) {
	e := newEgressEnv(t, "false") // default user provider, fresh data dir, no migrations
	if _, ok := e.auth.userProvider.(*dbUserProvider); !ok {
		t.Fatalf("default provider is %T, want *dbUserProvider", e.auth.userProvider)
	}
	if _, err := e.auth.userProvider.ListUsers(t.Context()); !errors.Is(err, errUserStoreNotProvisioned) {
		t.Fatalf("ListUsers on an unmigrated DB: %v, want errUserStoreNotProvisioned", err)
	}
	e.auth.config.loginEnabled = true
	e.auth.config.loginUser = loginCredential{Email: "root@example.com", Subject: "root-sub", Active: true}
	for _, id := range []string{"bootstrap", "root-sub", "root@example.com"} {
		rec := e.post(t, e.alice, "/api/v1/api-keys", map[string]any{"name": "x", "principal_id": id, "role": "pki-admin", "scopes": []string{"*"}})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("principal_id=%q: want 400, got %d", id, rec.Code)
		}
	}
	rec := e.post(t, e.alice, "/api/v1/api-keys", map[string]any{"name": "x", "principal_id": "svc-deploy", "role": "pki-admin", "scopes": []string{"*"}})
	if rec.Code != http.StatusCreated {
		t.Fatalf("default install without a user table must mint: %d %s", rec.Code, rec.Body.String())
	}
}

// The compose default (KRYPTKEEPER_DB_MODE=sqlite, no APP_USER_PROVIDER) opens
// the core DB, which runs the migrations; the default provider then lists
// users normally and key creation works.
func TestAPIKeyCreateWithMigratedDefaultUserStore(t *testing.T) {
	e := newEgressEnv(t, "false")
	t.Setenv("KRYPTKEEPER_DB_MODE", "sqlite")
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir()) // a clean DB, as on first boot
	db, _, err := OpenCoreDB()
	if err != nil {
		t.Fatalf("OpenCoreDB: %v", err)
	}
	defer db.Close()
	e.auth.userProvider = NewUserProviderFromEnv()
	if _, err := e.auth.userProvider.ListUsers(t.Context()); err != nil {
		t.Fatalf("ListUsers on a migrated DB: %v", err)
	}
	rec := e.post(t, e.alice, "/api/v1/api-keys", map[string]any{"name": "x", "principal_id": "svc-deploy", "role": "pki-admin", "scopes": []string{"*"}})
	if rec.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", rec.Code, rec.Body.String())
	}
}

// A configured store that errors (here: a closed database) is an outage and
// must refuse, not be mistaken for "no user store".
func TestAPIKeyCreateFailsClosedOnConfiguredStoreOutage(t *testing.T) {
	e := newEgressEnv(t, "false")
	db, err := sql.Open("sqlite", "file:"+t.TempDir()+"/u.db")
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	e.auth.userProvider = &dbUserProvider{db: db}
	rec := e.post(t, e.alice, "/api/v1/api-keys", map[string]any{"name": "x", "principal_id": "svc-deploy", "role": "pki-admin", "scopes": []string{"*"}})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("closed user DB: want 503, got %d: %s", rec.Code, rec.Body.String())
	}
}
