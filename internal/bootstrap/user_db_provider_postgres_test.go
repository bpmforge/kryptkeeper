// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"testing"
)

// migratedPostgresForTest resets the live test database, applies every
// migration, and leaves the DSN envs pointing at it so a provider built with
// the usual New...FromEnv constructor talks to Postgres.
func migratedPostgresForTest(t *testing.T) {
	t.Helper()
	freshPostgresForTest(t)
	db, isPG, err := OpenCoreDB()
	if err != nil {
		t.Fatalf("OpenCoreDB: %v", err)
	}
	if !isPG {
		t.Fatal("expected postgres core DB")
	}
	_ = db.Close()
}

// Regression for the rc.4 upgrade-test finding: ListUsers used
// COALESCE(last_login_at,”) on a timestamptz and scanned BOOLEAN active into
// an int, so GET /api/v1/users and POST /api/v1/api-keys (principalIDReserved)
// returned 503 on Postgres.
func TestDBUserProvider_Postgres_CRUDRoundTrip(t *testing.T) {
	migratedPostgresForTest(t)
	p, ok := newDBUserProviderFromEnv().(*dbUserProvider)
	if !ok || !p.postgres {
		t.Fatalf("expected a postgres dbUserProvider, got %T", p)
	}
	ctx := context.Background()

	// Empty store must list cleanly (the original failure was independent of data).
	if _, err := p.ListUsers(ctx); err != nil {
		t.Fatalf("ListUsers on empty users table: %v", err)
	}

	created, err := p.InviteUser(ctx, "alice@example.com", "pki-viewer")
	if err != nil {
		t.Fatalf("InviteUser: %v", err)
	}
	if !uuidRe.MatchString(created.ID) || created.Status != "active" {
		t.Fatalf("created = %+v", created)
	}

	users, err := p.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	got, found := userByID(users, created.ID)
	if !found || got.Email != "alice@example.com" || got.Status != "active" || got.CreatedAt == "" {
		t.Fatalf("ListUsers = %+v", users)
	}

	updated, err := p.UpdateUser(ctx, created.ID, "pki-operator", "")
	if err != nil || updated.Role != "pki-operator" || updated.Status != "active" {
		t.Fatalf("UpdateUser role: %+v err=%v", updated, err)
	}
	updated, err = p.UpdateUser(ctx, created.ID, "", "deactivated")
	if err != nil || updated.Status != "deactivated" {
		t.Fatalf("UpdateUser status: %+v err=%v", updated, err)
	}
	updated, err = p.UpdateUser(ctx, created.ID, "", "active")
	if err != nil || updated.Status != "active" {
		t.Fatalf("UpdateUser reactivate: %+v err=%v", updated, err)
	}

	if err := p.LinkOIDCIdentity(ctx, created.ID, "https://issuer.example", "sub-1"); err != nil {
		t.Fatalf("LinkOIDCIdentity: %v", err)
	}
	byOIDC, ok, err := p.FindByOIDCIdentity(ctx, "https://issuer.example", "sub-1")
	if err != nil || !ok || byOIDC.ID != created.ID {
		t.Fatalf("FindByOIDCIdentity = %+v ok=%v err=%v", byOIDC, ok, err)
	}
	if _, ok, err := p.FindByOIDCIdentity(ctx, "https://issuer.example", "nope"); err != nil || ok {
		t.Fatalf("FindByOIDCIdentity miss: ok=%v err=%v", ok, err)
	}

	if err := p.DeactivateUser(ctx, created.ID); err != nil {
		t.Fatalf("DeactivateUser: %v", err)
	}
	users, err = p.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers after deactivate: %v", err)
	}
	if u, found := userByID(users, created.ID); !found || u.Status != "deactivated" {
		t.Fatalf("expected soft-deleted user, got %+v", users)
	}

	// A malformed id is "not found", not a driver error.
	if err := p.DeactivateUser(ctx, "usr-123"); err == nil {
		t.Fatal("expected not-found for a non-UUID id")
	}
	if _, err := p.UpdateUser(ctx, "usr-123", "pki-viewer", ""); err == nil {
		t.Fatal("expected not-found for a non-UUID id")
	}

	if err := p.LinkOIDCIdentity(ctx, "usr-123", "https://issuer.example", "x"); err == nil {
		t.Fatal("LinkOIDCIdentity must report not-found for a non-UUID id")
	}

	// The reserved-principal check behind POST /api/v1/api-keys walks ListUsers.
	if _, err := p.ListUsers(ctx); err != nil {
		t.Fatalf("ListUsers (principalIDReserved path): %v", err)
	}
}
