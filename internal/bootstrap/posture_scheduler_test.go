// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"testing"
	"time"
)

func TestPostureSchedulerCaptureStoresSnapshot(t *testing.T) {
	store := newTestPostureStore(t)
	certs := &reportCertProvider{items: []CertificateItem{
		{FingerprintSHA256: "fp-1", PublicKeyAlgorithm: "RSA", ValidUntil: time.Now().UTC().Add(30 * 24 * time.Hour).Format(time.RFC3339)},
		{FingerprintSHA256: "fp-2", PublicKeyAlgorithm: "ECDSA", ValidUntil: time.Now().UTC().Add(365 * 24 * time.Hour).Format(time.RFC3339)},
	}}
	s := &PostureScheduler{certProvider: certs, store: store}

	s.capture()

	got, err := store.List(context.Background(), "2000-01-01T00:00:00Z", 100)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 snapshot after capture, got %d", len(got))
	}
	if got[0].TotalCerts != 2 {
		t.Fatalf("expected 2 certs in snapshot, got %d", got[0].TotalCerts)
	}
}

func TestPostureSchedulerCaptureDedupesWithinDay(t *testing.T) {
	store := newTestPostureStore(t)
	certs := &reportCertProvider{items: []CertificateItem{
		{FingerprintSHA256: "fp-1", PublicKeyAlgorithm: "RSA", ValidUntil: time.Now().UTC().Add(30 * 24 * time.Hour).Format(time.RFC3339)},
	}}
	s := &PostureScheduler{certProvider: certs, store: store}

	s.capture()
	s.capture() // same UTC day — must be a no-op

	got, err := store.List(context.Background(), "2000-01-01T00:00:00Z", 100)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected dedupe to 1 snapshot, got %d", len(got))
	}
}

func TestPostureSchedulerCaptureNilGuards(t *testing.T) {
	// Must not panic with nil store or provider.
	(&PostureScheduler{}).capture()
}

// TestPostureSchedulerCapture_FindingFunnelReflectsActiveException is the
// W2-12 acceptance-3 regression for the persisted trend-snapshot surface:
// an active accepted-risk exception must move a captured snapshot's
// Findings.Effective count (raw stays put, suppressed reflects the match).
// The persisted snapshot's Report field embeds the whole
// CryptoPostureReport (snapshotFromReport), so it round-trips onto
// GET /reports/crypto-posture/trend with no further wiring.
func TestPostureSchedulerCapture_FindingFunnelReflectsActiveException(t *testing.T) {
	store := newTestPostureStore(t)
	excStore := newFreshFindingExceptionStore(t)
	now := time.Now().UTC()

	exc := FindingException{
		ID: "exc-snapshot-funnel", TargetType: FindingExceptionTargetCertificate, TargetID: "fp-weak",
		FindingCode: "WEAK_RSA_KEY", JustificationCode: JustificationRiskAccepted,
		CreatedBy: "alice", CreatedAt: now.Format(time.RFC3339),
		ExpiresAt: now.Add(24 * time.Hour).Format(time.RFC3339), // active
	}
	if err := excStore.Create(context.Background(), exc); err != nil {
		t.Fatalf("create exception: %v", err)
	}

	certs := &reportCertProvider{items: findingFunnelTestCerts()}
	s := &PostureScheduler{certProvider: certs, store: store, exceptionStore: excStore}
	s.capture()

	got, err := store.List(context.Background(), "2000-01-01T00:00:00Z", 100)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 snapshot after capture, got %d", len(got))
	}
	findings := got[0].Report.Findings
	if findings.Raw != 2 {
		t.Fatalf("expected raw to stay 2, got %d", findings.Raw)
	}
	if findings.Suppressed != 1 {
		t.Fatalf("expected 1 suppressed finding with an active exception, got %d", findings.Suppressed)
	}
	if findings.Effective != 1 {
		t.Fatalf("expected effective 1 with an active exception, got %d", findings.Effective)
	}
}

// TestPostureSchedulerCapture_FindingFunnelReturnsAfterExpiry is the same
// acceptance-3 regression's other half: once an exception has lapsed, the
// finding it used to cover must count again. The store holds TWO
// exceptions — one still active on fp-weak/WEAK_RSA_KEY, one already
// expired on fp-weak/SAN_SPRAWL — so the assertion (suppressed==1, not 0 or
// 2) can only pass if expiry filtering actually ran: a scheduler with the
// exceptionStore wiring removed would suppress both (suppressed==2), and a
// scheduler that failed to filter by expiry at all would also suppress
// both, while this proves exactly the lapsed one reopened.
func TestPostureSchedulerCapture_FindingFunnelReturnsAfterExpiry(t *testing.T) {
	store := newTestPostureStore(t)
	excStore := newFreshFindingExceptionStore(t)
	now := time.Now().UTC()

	active := FindingException{
		ID: "exc-snapshot-funnel-active", TargetType: FindingExceptionTargetCertificate, TargetID: "fp-weak",
		FindingCode: "WEAK_RSA_KEY", JustificationCode: JustificationRiskAccepted,
		CreatedBy: "alice", CreatedAt: now.Format(time.RFC3339),
		ExpiresAt: now.Add(24 * time.Hour).Format(time.RFC3339), // active
	}
	lapsed := FindingException{
		ID: "exc-snapshot-funnel-lapsed", TargetType: FindingExceptionTargetCertificate, TargetID: "fp-weak",
		FindingCode: "SAN_SPRAWL", JustificationCode: JustificationRiskAccepted,
		CreatedBy: "alice", CreatedAt: now.Add(-48 * time.Hour).Format(time.RFC3339),
		ExpiresAt: now.Add(-24 * time.Hour).Format(time.RFC3339), // expired
	}
	for _, exc := range []FindingException{active, lapsed} {
		if err := excStore.Create(context.Background(), exc); err != nil {
			t.Fatalf("create exception %s: %v", exc.ID, err)
		}
	}

	certs := &reportCertProvider{items: findingFunnelTestCerts()}
	s := &PostureScheduler{certProvider: certs, store: store, exceptionStore: excStore}
	s.capture()

	got, err := store.List(context.Background(), "2000-01-01T00:00:00Z", 100)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 snapshot after capture, got %d", len(got))
	}
	findings := got[0].Report.Findings
	if findings.Raw != 2 {
		t.Fatalf("expected raw to remain 2, got %d", findings.Raw)
	}
	if findings.Suppressed != 1 {
		t.Fatalf("expected exactly 1 suppressed (the still-active exception; the lapsed one reopened), got %d", findings.Suppressed)
	}
	if findings.Effective != 1 {
		t.Fatalf("expected effective 1 (raw 2 - suppressed 1), got %d", findings.Effective)
	}
}

func TestPostureSchedulerCaptureSkipsWhenNotLeader(t *testing.T) {
	store := newTestPostureStore(t)
	certs := &reportCertProvider{items: []CertificateItem{
		{FingerprintSHA256: "fp-1", PublicKeyAlgorithm: "RSA", ValidUntil: time.Now().UTC().Add(30 * 24 * time.Hour).Format(time.RFC3339)},
	}}

	db := newTestHADB(t)
	now := time.Now().UTC()
	// A peer replica holds a live lease on this scheduler's lock.
	peer := newTestHACoordinatorAt(t, db, "replica-peer", now)
	if ok, err := peer.TryAcquire(context.Background(), haLockPostureScheduler, 5*time.Minute); err != nil || !ok {
		t.Fatalf("setup: peer acquire ok=%v err=%v", ok, err)
	}
	self := newTestHACoordinatorAt(t, db, "replica-self", now)

	s := &PostureScheduler{certProvider: certs, store: store, pollInterval: time.Hour, haCoordinator: self}
	s.capture()

	got, err := store.List(context.Background(), "2000-01-01T00:00:00Z", 100)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected non-leader capture to skip, got %d snapshot(s)", len(got))
	}
}

func TestPostureSchedulerCaptureRunsWhenLeader(t *testing.T) {
	store := newTestPostureStore(t)
	certs := &reportCertProvider{items: []CertificateItem{
		{FingerprintSHA256: "fp-1", PublicKeyAlgorithm: "RSA", ValidUntil: time.Now().UTC().Add(30 * 24 * time.Hour).Format(time.RFC3339)},
	}}

	db := newTestHADB(t)
	self := newTestHACoordinatorAt(t, db, "replica-self", time.Now().UTC())

	s := &PostureScheduler{certProvider: certs, store: store, pollInterval: time.Hour, haCoordinator: self}
	s.capture()

	got, err := store.List(context.Background(), "2000-01-01T00:00:00Z", 100)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected leader capture to store a snapshot, got %d", len(got))
	}
}
