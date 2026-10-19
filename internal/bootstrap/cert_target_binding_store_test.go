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
	"time"

	_ "modernc.org/sqlite"
)

func newFreshBindingStore(t *testing.T) *sqlCertTargetBindingStore {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "bindings.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	s := &sqlCertTargetBindingStore{db: db}
	if err := s.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}
	return s
}

func TestCertTargetBindingStoreLifecycle(t *testing.T) {
	ctx := context.Background()
	s := newFreshBindingStore(t)

	created, err := s.Create(ctx, CertTargetBinding{CertFingerprint: "fp1", TargetID: "t1", CreatedBy: "alice"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.ServedFingerprint != "fp1" || created.Tenant != DefaultTenant || created.Source != bindingSourceOperator || created.CreatedAt == "" {
		t.Fatalf("defaults not applied: %+v", created)
	}
	if _, err := s.Create(ctx, CertTargetBinding{CertFingerprint: "fp1", TargetID: "t1"}); !errors.Is(err, errBindingExists) {
		t.Fatalf("duplicate create err = %v, want errBindingExists", err)
	}
	if _, err := s.Create(ctx, CertTargetBinding{CertFingerprint: "fp1", TargetID: "t2", Source: bindingSourceBackfill}); err != nil {
		t.Fatalf("second target: %v", err)
	}
	if _, err := s.Create(ctx, CertTargetBinding{CertFingerprint: "fp1", TargetID: "t3", Source: "bogus"}); err == nil {
		t.Fatal("the source CHECK constraint accepted an unknown source")
	}

	if got, _ := s.ListByTarget(ctx, "t1"); len(got) != 1 || got[0].CreatedBy != "alice" {
		t.Fatalf("ListByTarget = %+v", got)
	}
	if got, _ := s.ListAll(ctx); len(got) != 2 {
		t.Fatalf("ListAll = %+v", got)
	}

	if err := s.SetServed(ctx, "t1", "fp1", "fp2"); err != nil {
		t.Fatalf("SetServed: %v", err)
	}
	if got, _ := s.ListByTarget(ctx, "t1"); got[0].ServedFingerprint != "fp2" || got[0].CertFingerprint != "fp1" {
		t.Fatalf("SetServed did not move served only: %+v", got[0])
	}
	if err := s.AdvanceServed(ctx, "t1", "fp2", "fp3"); err != nil {
		t.Fatalf("AdvanceServed: %v", err)
	}
	if got, _ := s.ListByTarget(ctx, "t1"); got[0].ServedFingerprint != "fp3" {
		t.Fatalf("AdvanceServed = %+v", got[0])
	}
	if got, _ := s.ListByTarget(ctx, "t2"); got[0].ServedFingerprint != "fp1" {
		t.Fatalf("AdvanceServed leaked to another target: %+v", got[0])
	}

	if err := s.Delete(ctx, "t1", "fp1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := s.Delete(ctx, "t1", "fp1"); !errors.Is(err, errBindingNotFound) {
		t.Fatalf("second delete err = %v, want errBindingNotFound", err)
	}
	if err := s.DeleteByTarget(ctx, "t2"); err != nil {
		t.Fatalf("DeleteByTarget: %v", err)
	}
	if got, _ := s.ListAll(ctx); len(got) != 0 {
		t.Fatalf("rows left: %+v", got)
	}
}

func TestCertTargetBindingStoreBackfillFlag(t *testing.T) {
	ctx := context.Background()
	s := newFreshBindingStore(t)
	if done, err := s.BackfillDone(ctx); err != nil || done {
		t.Fatalf("fresh store backfill done = %v, %v", done, err)
	}
	for range 2 { // idempotent
		if err := s.MarkBackfillDone(ctx); err != nil {
			t.Fatalf("mark: %v", err)
		}
	}
	if done, err := s.BackfillDone(ctx); err != nil || !done {
		t.Fatalf("after mark done = %v, %v", done, err)
	}
}

func TestCertTargetBindingPostgresPlaceholders(t *testing.T) {
	pg := &sqlCertTargetBindingStore{postgres: true}
	if got := pg.q("a = ? AND b = ? AND c = ?"); got != "a = $1 AND b = $2 AND c = $3" {
		t.Fatalf("rebound = %q", got)
	}
	if got := (&sqlCertTargetBindingStore{}).q("a = ?"); got != "a = ?" {
		t.Fatalf("sqlite statement rewritten: %q", got)
	}
}

func TestBackfillBindingsOnlyLiveHeadCertsOnMatchingHosts(t *testing.T) {
	ctx := context.Background()
	s := newFreshBindingStore(t)
	now := time.Now().UTC()
	live := now.Add(10 * 24 * time.Hour).Format(time.RFC3339)
	succ := "next"
	revoked := now.Format(time.RFC3339)
	eligible := []ManagedTarget{
		{ID: "t1", Host: "a.example.com", Tenant: "acme"},
		{ID: "t2", Host: "a.example.com"}, // two targets, one host: both bound
		{ID: "t3", Host: "other.example.com"},
	}
	certs := []CertificateItem{
		{FingerprintSHA256: "live", CommonName: "a.example.com", ValidUntil: live},
		{FingerprintSHA256: "san", CommonName: "x", SubjectAltNames: []string{"other.example.com"}, ValidUntil: live},
		{FingerprintSHA256: "superseded", CommonName: "a.example.com", ValidUntil: live, SuccessorFP: &succ},
		{FingerprintSHA256: "revoked", CommonName: "a.example.com", ValidUntil: live, RevokedAt: &revoked},
		{FingerprintSHA256: "expired", CommonName: "a.example.com", ValidUntil: now.Add(-time.Hour).Format(time.RFC3339)},
	}
	n, err := backfillBindings(ctx, s, certs, eligible, now)
	if err != nil || n != 3 {
		t.Fatalf("backfill = %d, %v; want 3 (live x2 targets, san x1)", n, err)
	}
	all, _ := s.ListAll(ctx)
	for _, b := range all {
		if b.Source != bindingSourceBackfill {
			t.Fatalf("backfilled row has source %q", b.Source)
		}
		if b.CertFingerprint != "live" && b.CertFingerprint != "san" {
			t.Fatalf("backfill bound %q", b.CertFingerprint)
		}
	}
	if again, err := backfillBindings(ctx, s, certs, eligible, now); err != nil || again != 0 {
		t.Fatalf("re-running created %d binding(s), %v", again, err)
	}
}
