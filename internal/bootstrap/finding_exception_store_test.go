// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func newFreshFindingExceptionStore(t *testing.T) *sqliteFindingExceptionStore {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "finding-exceptions-fresh.db"))
	if err != nil {
		t.Fatalf("open fresh db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	s := &sqliteFindingExceptionStore{db: db}
	if err := s.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("EnsureSchema on fresh db: %v", err)
	}
	return s
}

// TestFindingExceptionStoreSelfHealsSchemaOnFreshDB is the W2-06/G-33
// regression: a brand-new database with no pre-existing finding_exceptions
// table must still work, and EnsureSchema must be idempotent (safe on every
// process restart), matching the S-06/S-07/W2-05 self-heal precedent.
func TestFindingExceptionStoreSelfHealsSchemaOnFreshDB(t *testing.T) {
	s := newFreshFindingExceptionStore(t)
	ctx := context.Background()

	now := time.Now().UTC()
	exc := FindingException{
		ID:                "exc-1",
		TargetType:        FindingExceptionTargetCertificate,
		TargetID:          "fp-legacy-cert",
		FindingCode:       "WEAK_RSA_KEY",
		JustificationCode: JustificationRiskAccepted,
		JustificationNote: "scheduled decommission Q3",
		CreatedBy:         "alice",
		CreatedAt:         now.Format(time.RFC3339),
		ExpiresAt:         now.Add(30 * 24 * time.Hour).Format(time.RFC3339),
	}
	if err := s.Create(ctx, exc); err != nil {
		t.Fatalf("Create on fresh db: %v", err)
	}

	got, err := s.Get(ctx, "exc-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.TargetID != exc.TargetID || got.FindingCode != exc.FindingCode || got.JustificationNote != exc.JustificationNote {
		t.Fatalf("unexpected round-trip: %+v", got)
	}

	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatalf("EnsureSchema again: %v", err)
	}
}

// TestFindingExceptionStore_RejectsInvalidEnums proves the fixed-enum CHECK
// constraints on target_type and justification_code are actually enforced
// by the schema, not just documented — a bad value must error, not silently
// insert.
func TestFindingExceptionStore_RejectsInvalidEnums(t *testing.T) {
	s := newFreshFindingExceptionStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	badTargetType := FindingException{
		ID: "exc-bad-target", TargetType: "endpoint", TargetID: "x",
		FindingCode: "X", JustificationCode: JustificationRiskAccepted,
		CreatedBy: "alice", CreatedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
	}
	if err := s.Create(ctx, badTargetType); err == nil {
		t.Error("expected an error for an invalid target_type, got none")
	}

	badJustification := FindingException{
		ID: "exc-bad-just", TargetType: FindingExceptionTargetCA, TargetID: "ca-1",
		FindingCode: "X", JustificationCode: "because_i_said_so",
		CreatedBy: "alice", CreatedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
	}
	if err := s.Create(ctx, badJustification); err == nil {
		t.Error("expected an error for an invalid justification_code, got none")
	}
}

// TestFindingExceptionStore_ListForTarget proves exceptions are scoped per
// target and don't leak across certs/CAs.
func TestFindingExceptionStore_ListForTarget(t *testing.T) {
	s := newFreshFindingExceptionStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	mk := func(id, targetID string) FindingException {
		return FindingException{
			ID: id, TargetType: FindingExceptionTargetCertificate, TargetID: targetID,
			FindingCode: "SAN_SPRAWL", JustificationCode: JustificationFalsePositive,
			CreatedBy: "bob", CreatedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
		}
	}
	for _, exc := range []FindingException{mk("exc-a1", "fp-a"), mk("exc-a2", "fp-a"), mk("exc-b1", "fp-b")} {
		if err := s.Create(ctx, exc); err != nil {
			t.Fatalf("create %s: %v", exc.ID, err)
		}
	}

	fpA, err := s.ListForTarget(ctx, FindingExceptionTargetCertificate, "fp-a")
	if err != nil {
		t.Fatalf("ListForTarget fp-a: %v", err)
	}
	if len(fpA) != 2 {
		t.Fatalf("expected 2 exceptions for fp-a, got %d", len(fpA))
	}

	fpB, err := s.ListForTarget(ctx, FindingExceptionTargetCertificate, "fp-b")
	if err != nil {
		t.Fatalf("ListForTarget fp-b: %v", err)
	}
	if len(fpB) != 1 {
		t.Fatalf("expected 1 exception for fp-b, got %d", len(fpB))
	}

	none, err := s.ListForTarget(ctx, FindingExceptionTargetCertificate, "fp-nonexistent")
	if err != nil {
		t.Fatalf("ListForTarget fp-nonexistent: %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("expected 0 exceptions for an unknown target, got %d", len(none))
	}
}

// TestFindingExceptionStore_Delete proves an exception can be manually
// revoked before its natural expiry, and that deleting an unknown ID errors
// rather than silently succeeding.
func TestFindingExceptionStore_Delete(t *testing.T) {
	s := newFreshFindingExceptionStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	exc := FindingException{
		ID: "exc-revoke-me", TargetType: FindingExceptionTargetCA, TargetID: "ca-1",
		FindingCode: "WEAK_SIGNATURE", JustificationCode: JustificationPlannedRemediation,
		CreatedBy: "carol", CreatedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
	}
	if err := s.Create(ctx, exc); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.Delete(ctx, "exc-revoke-me"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.Get(ctx, "exc-revoke-me"); err != errFindingExceptionNotFound {
		t.Fatalf("expected errFindingExceptionNotFound after delete, got %v", err)
	}
	if err := s.Delete(ctx, "exc-does-not-exist"); err != errFindingExceptionNotFound {
		t.Fatalf("expected errFindingExceptionNotFound deleting an unknown id, got %v", err)
	}
}

// TestFindingException_IsActive is the auto-reopen/expiry regression: an
// exception is active strictly before its expiry and inactive at/after it,
// and an unparseable ExpiresAt fails closed (inactive) rather than
// defaulting to permanently active.
func TestFindingException_IsActive(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)

	future := FindingException{ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)}
	if !future.IsActive(now) {
		t.Error("expected an exception expiring in the future to be active")
	}

	past := FindingException{ExpiresAt: now.Add(-time.Hour).Format(time.RFC3339)}
	if past.IsActive(now) {
		t.Error("expected a lapsed exception to be inactive")
	}

	malformed := FindingException{ExpiresAt: "not-a-timestamp"}
	if malformed.IsActive(now) {
		t.Error("expected an unparseable expires_at to fail closed (inactive), not permanently active")
	}
}

// TestFindingExceptionStore_ListActive is the W2-11 regression for the bulk
// read the finding funnel needs: it must return exceptions from every
// target in one call, must exclude an already-lapsed exception, and a
// still-active one must drop out of a second ListActive call once now moves
// past its expires_at — this is the funnel's "suppressed reflects an active
// exception and drops back out when that exception expires" acceptance
// criterion, proven directly against the store rather than through a
// report handler.
func TestFindingExceptionStore_ListActive(t *testing.T) {
	s := newFreshFindingExceptionStore(t)
	ctx := context.Background()
	expiresAt := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)

	active := FindingException{
		ID: "exc-active", TargetType: FindingExceptionTargetCertificate, TargetID: "fp-a",
		FindingCode: "WEAK_RSA_KEY", JustificationCode: JustificationRiskAccepted,
		CreatedBy: "alice", CreatedAt: expiresAt.Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt: expiresAt.Format(time.RFC3339),
	}
	lapsed := FindingException{
		ID: "exc-lapsed", TargetType: FindingExceptionTargetCA, TargetID: "ca-1",
		FindingCode: "WEAK_SIGNATURE", JustificationCode: JustificationFalsePositive,
		CreatedBy: "bob", CreatedAt: expiresAt.Add(-48 * time.Hour).Format(time.RFC3339),
		ExpiresAt: expiresAt.Add(-24 * time.Hour).Format(time.RFC3339),
	}
	for _, exc := range []FindingException{active, lapsed} {
		if err := s.Create(ctx, exc); err != nil {
			t.Fatalf("create %s: %v", exc.ID, err)
		}
	}

	beforeExpiry := expiresAt.Add(-time.Minute)
	got, err := s.ListActive(ctx, beforeExpiry)
	if err != nil {
		t.Fatalf("ListActive before expiry: %v", err)
	}
	if len(got) != 1 || got[0].ID != "exc-active" {
		t.Fatalf("expected only exc-active before expiry, got %+v", got)
	}

	afterExpiry := expiresAt.Add(time.Minute)
	got, err = s.ListActive(ctx, afterExpiry)
	if err != nil {
		t.Fatalf("ListActive after expiry: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no active exceptions after exc-active's own expiry, got %+v", got)
	}
}

// TestFindingExceptionIndex proves findingExceptionIndex/findingExceptionKey
// round-trip an active exception into a lookup a funnel can check in O(1),
// and that a different target or finding code is a miss, not a false hit.
func TestFindingExceptionIndex(t *testing.T) {
	idx := findingExceptionIndex([]FindingException{
		{TargetType: FindingExceptionTargetCertificate, TargetID: "fp-a", FindingCode: "WEAK_RSA_KEY"},
	})
	if !idx[findingExceptionKey(FindingExceptionTargetCertificate, "fp-a", "WEAK_RSA_KEY")] {
		t.Error("expected an exact (target_type, target_id, finding_code) match to hit")
	}
	if idx[findingExceptionKey(FindingExceptionTargetCertificate, "fp-b", "WEAK_RSA_KEY")] {
		t.Error("expected a different target_id to miss")
	}
	if idx[findingExceptionKey(FindingExceptionTargetCertificate, "fp-a", "SAN_SPRAWL")] {
		t.Error("expected a different finding_code to miss")
	}
}

// TestFindingException_CertScopedExceptionDoesNotApplyToReissuedCert is the
// design doc's "auto-reopen on re-issuance is structural" claim, made
// concrete: an exception filed against an old certificate's fingerprint
// simply has no row matching a newly-issued certificate's (different)
// fingerprint — ListForTarget on the NEW fingerprint returns nothing, with
// no reconciliation code involved.
func TestFindingException_CertScopedExceptionDoesNotApplyToReissuedCert(t *testing.T) {
	s := newFreshFindingExceptionStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	oldFingerprint := "fp-original-issuance"
	newFingerprint := "fp-after-renewal" // a real renewal always produces a different fingerprint

	exc := FindingException{
		ID: "exc-old-cert", TargetType: FindingExceptionTargetCertificate, TargetID: oldFingerprint,
		FindingCode: "WEAK_RSA_KEY", JustificationCode: JustificationRiskAccepted,
		CreatedBy: "dave", CreatedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(365 * 24 * time.Hour).Format(time.RFC3339),
	}
	if err := s.Create(ctx, exc); err != nil {
		t.Fatalf("create: %v", err)
	}

	stillOnOld, err := s.ListForTarget(ctx, FindingExceptionTargetCertificate, oldFingerprint)
	if err != nil {
		t.Fatalf("ListForTarget old: %v", err)
	}
	if len(stillOnOld) != 1 {
		t.Fatalf("expected the exception to still apply to the original fingerprint, got %d", len(stillOnOld))
	}

	onNew, err := s.ListForTarget(ctx, FindingExceptionTargetCertificate, newFingerprint)
	if err != nil {
		t.Fatalf("ListForTarget new: %v", err)
	}
	if len(onNew) != 0 {
		t.Fatalf("expected the renewed certificate's new fingerprint to have no exception (auto-reopened), got %d", len(onNew))
	}
}
