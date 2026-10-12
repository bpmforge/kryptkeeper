// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	kkdb "kryptkeeper/internal/db"

	_ "modernc.org/sqlite"
)

func newFreshUserDBProvider(t *testing.T) *dbUserProvider {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "users-fresh.db"))
	if err != nil {
		t.Fatalf("open fresh db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := kkdb.RunMigrations(db, "sqlite"); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	return &dbUserProvider{db: db}
}

func TestDBUserProvider_InviteListUpdateDeactivateRoundTrip(t *testing.T) {
	p := newFreshUserDBProvider(t)
	ctx := context.Background()

	created, err := p.InviteUser(ctx, "alice@example.com", "pki-viewer")
	if err != nil {
		t.Fatalf("InviteUser: %v", err)
	}
	if created.ID == "" || created.Email != "alice@example.com" {
		t.Fatalf("created = %+v", created)
	}

	users, err := p.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if !containsUserID(users, created.ID) {
		t.Fatalf("expected ListUsers to include the newly invited user, got %+v", users)
	}

	updated, err := p.UpdateUser(ctx, created.ID, "pki-operator", "")
	if err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	if updated.Role != "pki-operator" {
		t.Fatalf("expected role pki-operator, got %q", updated.Role)
	}

	if err := p.DeactivateUser(ctx, created.ID); err != nil {
		t.Fatalf("DeactivateUser: %v", err)
	}
	users, err = p.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers after deactivate: %v", err)
	}
	deactivated, found := userByID(users, created.ID)
	if !found || deactivated.Status != "deactivated" {
		t.Fatalf("expected the account to remain (soft delete) as deactivated, got %+v", users)
	}
}

func containsUserID(users []UserRecord, id string) bool {
	_, found := userByID(users, id)
	return found
}

func userByID(users []UserRecord, id string) (UserRecord, bool) {
	for _, u := range users {
		if u.ID == id {
			return u, true
		}
	}
	return UserRecord{}, false
}

func TestDBUserProvider_DeactivateUnknownUserErrors(t *testing.T) {
	p := newFreshUserDBProvider(t)
	if err := p.DeactivateUser(context.Background(), "does-not-exist"); err == nil {
		t.Fatal("expected an error deactivating an unknown user")
	}
}

// TestDBUserProvider_LinkAndFindByOIDCIdentity exercises OIDCIdentityLinker
// (user_provider.go), using the oidc_subject/oidc_issuer columns migration
// 000001 already ships -- acceptance #2's "recorded identity source".
func TestDBUserProvider_LinkAndFindByOIDCIdentity(t *testing.T) {
	p := newFreshUserDBProvider(t)
	ctx := context.Background()

	created, err := p.InviteUser(ctx, "bob@example.com", "pki-viewer")
	if err != nil {
		t.Fatalf("InviteUser: %v", err)
	}

	if _, found, err := p.FindByOIDCIdentity(ctx, "https://idp.example.com/", "idp-subject-1"); err != nil || found {
		t.Fatalf("expected no identity link before LinkOIDCIdentity, found=%v err=%v", found, err)
	}

	if err := p.LinkOIDCIdentity(ctx, created.ID, "https://idp.example.com/", "idp-subject-1"); err != nil {
		t.Fatalf("LinkOIDCIdentity: %v", err)
	}

	user, found, err := p.FindByOIDCIdentity(ctx, "https://idp.example.com/", "idp-subject-1")
	if err != nil {
		t.Fatalf("FindByOIDCIdentity: %v", err)
	}
	if !found || user.ID != created.ID {
		t.Fatalf("expected to find %q by its linked OIDC identity, got found=%v user=%+v", created.ID, found, user)
	}
}

func TestDBUserProvider_FindByOIDCIdentity_WrongIssuerNoMatch(t *testing.T) {
	p := newFreshUserDBProvider(t)
	ctx := context.Background()

	created, err := p.InviteUser(ctx, "carol@example.com", "pki-viewer")
	if err != nil {
		t.Fatalf("InviteUser: %v", err)
	}
	if err := p.LinkOIDCIdentity(ctx, created.ID, "https://idp-a.example.com/", "subject-1"); err != nil {
		t.Fatalf("LinkOIDCIdentity: %v", err)
	}

	// Same subject value under a DIFFERENT issuer must not match -- two IdPs
	// could otherwise collide on subject alone.
	if _, found, err := p.FindByOIDCIdentity(ctx, "https://idp-b.example.com/", "subject-1"); err != nil || found {
		t.Fatalf("expected no match across a different issuer, found=%v err=%v", found, err)
	}
}
