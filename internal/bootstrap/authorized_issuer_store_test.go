// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestDBAuthorizedIssuerStore(t *testing.T) {
	db := setupIntegrationDB(t) // the real migrations create authorized_issuers
	s := &dbAuthorizedIssuerStore{db: db, ph: sqlitePlaceholder}
	ctx := context.Background()
	mk := func(id, tenant, value string) AuthorizedIssuer {
		return AuthorizedIssuer{ID: id, Tenant: tenant, Name: id, Kind: "issuer_dn", Value: value, CreatedBy: "t", CreatedAt: "2030-01-01T00:00:00Z"}
	}
	for _, a := range []AuthorizedIssuer{mk("a", "", "CN=A"), mk("b", "acme", "CN=A"), mk("c", "acme", "CN=C")} {
		if err := s.Create(ctx, a); err != nil {
			t.Fatalf("create %s: %v", a.ID, err)
		}
	}
	if err := s.Create(ctx, mk("dup", "acme", "CN=C")); !errors.Is(err, errAuthorizedIssuerExists) {
		t.Fatalf("duplicate in a tenant: %v", err)
	}
	acme := "acme"
	if got, err := s.List(ctx, &acme); err != nil || len(got) != 2 {
		t.Fatalf("acme list: %v %v", got, err)
	}
	if got, err := s.List(ctx, nil); err != nil || len(got) != 3 {
		t.Fatalf("all list: %v %v", got, err)
	}
	def := ""
	if got, _ := s.List(ctx, &def); len(got) != 1 || got[0].ID != "a" {
		t.Fatalf("default tenant list: %v", got)
	}
	if g, err := s.Get(ctx, "b"); err != nil || g.Tenant != "acme" || g.Value != "CN=A" {
		t.Fatalf("get: %+v %v", g, err)
	}
	if _, err := s.Get(ctx, "zzz"); !errors.Is(err, errAuthorizedIssuerNotFound) {
		t.Fatalf("get missing: %v", err)
	}
	if err := s.Delete(ctx, "b"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, "b"); !errors.Is(err, errAuthorizedIssuerNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
}

// A database the migrations never reached still answers: the classifier's
// source creates the table on first use and reports an empty set.
func TestDBAuthorizedSourceSelfHeals(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "bare.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	src := dbAuthorizedSource(db, sqlitePlaceholder)
	if got, err := src(context.Background(), ""); err != nil || len(got) != 0 {
		t.Fatalf("bare database: %v %v", got, err)
	}
}

func TestMemoryAuthorizedIssuerStoreMatchesDBSemantics(t *testing.T) {
	m := &memoryAuthorizedIssuerStore{}
	ctx := context.Background()
	a := AuthorizedIssuer{ID: "1", Tenant: "t", Kind: "issuer_dn", Value: "CN=x"}
	if err := m.Create(ctx, a); err != nil {
		t.Fatal(err)
	}
	b := a
	b.ID = "2"
	if err := m.Create(ctx, b); !errors.Is(err, errAuthorizedIssuerExists) {
		t.Fatal("duplicate must be rejected")
	}
	if err := m.Delete(ctx, "1"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Get(ctx, "1"); !errors.Is(err, errAuthorizedIssuerNotFound) {
		t.Fatal("deleted row still readable")
	}
}
