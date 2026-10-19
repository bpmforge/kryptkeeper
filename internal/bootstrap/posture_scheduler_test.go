// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"strings"
	"sync"
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

type failingCertProvider struct{ reportCertProvider }

func (p *failingCertProvider) ListCertificates(context.Context, CertificateListQuery) (CertificateListResult, error) {
	return CertificateListResult{}, errors.New("boom")
}

// blindLatestStore hides existing rows from the UTC-day dedupe so only the
// HA lease can prevent a double write.
type blindLatestStore struct{ PostureSnapshotStore }

func (blindLatestStore) Latest(context.Context) (PostureSnapshot, bool, error) {
	return PostureSnapshot{}, false, nil
}

type alertRecorder struct {
	mu     sync.Mutex
	events []string
}

func (r *alertRecorder) sink(_ context.Context, event, _ string) {
	r.mu.Lock()
	r.events = append(r.events, event)
	r.mu.Unlock()
}

func TestPostureRetentionFloorRejectedAtStartup(t *testing.T) {
	for _, bad := range []string{"399", "abc"} {
		t.Setenv("POSTURE_RETENTION_DAYS", bad)
		if err := ValidatePostureRetentionFromEnv(); err == nil {
			t.Fatalf("POSTURE_RETENTION_DAYS=%q must be rejected", bad)
		}
	}
	for env, want := range map[string]int{"400": 400, "730": 730, "": 400} {
		t.Setenv("POSTURE_RETENTION_DAYS", env)
		got, err := postureRetentionDaysFromEnv()
		if err != nil || got != want {
			t.Fatalf("env %q: got %d, %v; want %d", env, got, err, want)
		}
	}

	store := newTestPostureStore(t)
	certs := &reportCertProvider{items: []CertificateItem{{FingerprintSHA256: "fp-1", PublicKeyAlgorithm: "RSA"}}}
	s := &PostureScheduler{certProvider: certs, store: store, pollInterval: time.Hour,
		configErr: errors.New("bad retention"), stop: make(chan struct{})}
	s.Start()
	time.Sleep(50 * time.Millisecond)
	s.Stop()
	if got, _ := store.List(context.Background(), "2000-01-01T00:00:00Z", 10); len(got) != 0 {
		t.Fatalf("disabled scheduler must not capture, got %d rows", len(got))
	}
}

func TestPostureSchedulerPruneWritesAudit(t *testing.T) {
	store := newTestPostureStore(t)
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	old := now.AddDate(0, 0, -401).Format(time.RFC3339)
	if err := store.Save(context.Background(), snapshotFromReport("psn-old", old, sampleReport(1, 1, 1))); err != nil {
		t.Fatal(err)
	}
	audit := &recordingAuditProvider{}
	s := &PostureScheduler{certProvider: &reportCertProvider{}, store: store, pollInterval: 24 * time.Hour,
		retentionDays: 400, clock: func() time.Time { return now }}
	s.WithAudit(audit)

	s.capture()
	prunes := func() []AuditEntry {
		audit.mu.Lock()
		defer audit.mu.Unlock()
		var out []AuditEntry
		for _, e := range audit.entries {
			if e.Action == "posture.snapshot_prune" {
				out = append(out, e)
			}
		}
		return out
	}
	got := prunes()
	if len(got) != 1 {
		t.Fatalf("expected 1 prune audit entry, got %d", len(got))
	}
	for _, want := range []string{"deleted=1", "oldest=" + old, "newest=" + old} {
		if !strings.Contains(got[0].ChangeSummary, want) {
			t.Fatalf("summary %q missing %q", got[0].ChangeSummary, want)
		}
	}
	s.prune(context.Background(), now)
	if len(prunes()) != 1 {
		t.Fatal("prune with nothing to delete must not audit")
	}
}

func TestPostureSchedulerMissedSnapshotEvent(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	run := func(t *testing.T, age time.Duration, certs CertificateProvider, captures int) []string {
		store := newTestPostureStore(t)
		ts := now.Add(-age).Format(time.RFC3339)
		if err := store.Save(context.Background(), snapshotFromReport("psn-1", ts, sampleReport(1, 1, 1))); err != nil {
			t.Fatal(err)
		}
		rec := &alertRecorder{}
		s := &PostureScheduler{certProvider: certs, store: store, pollInterval: 24 * time.Hour,
			alerts: rec.sink, clock: func() time.Time { return now }}
		for i := 0; i < captures; i++ {
			s.capture()
		}
		return rec.events
	}
	if ev := run(t, 49*time.Hour, &reportCertProvider{}, 1); len(ev) != 1 || ev[0] != AlertEventPostureSnapshotMissed {
		t.Fatalf("49h gap: got events %v", ev)
	}
	if ev := run(t, 47*time.Hour, &reportCertProvider{}, 1); len(ev) != 0 {
		t.Fatalf("47h gap must not alert, got %v", ev)
	}
	if ev := run(t, 49*time.Hour, &failingCertProvider{}, 2); len(ev) != 1 {
		t.Fatalf("repeated failing runs must alert once, got %v", ev)
	}
}

func TestPostureSchedulersTwoReplicasProduceOneSnapshot(t *testing.T) {
	at := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	haDB := newTestHADB(t)
	store := newTestPostureStore(t)
	certs := &reportCertProvider{items: []CertificateItem{{FingerprintSHA256: "fp-1", PublicKeyAlgorithm: "RSA"}}}
	mk := func(replica string) *PostureScheduler {
		return &PostureScheduler{certProvider: certs, store: blindLatestStore{store}, pollInterval: 24 * time.Hour,
			haCoordinator: newTestHACoordinatorAt(t, haDB, replica, at), clock: func() time.Time { return at }}
	}
	count := func() int {
		got, err := store.List(context.Background(), "2000-01-01T00:00:00Z", 100)
		if err != nil {
			t.Fatal(err)
		}
		return len(got)
	}
	mk("replica-a").capture()
	if count() != 1 {
		t.Fatalf("leader must save 1 snapshot, got %d", count())
	}
	mk("replica-b").capture()
	if count() != 1 {
		t.Fatalf("non-holder must save nothing, got %d rows", count())
	}
}
