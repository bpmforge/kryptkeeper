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

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

// W9-09: per-key ACL, max-age rotation sweep, compromise flow.

const keyLifecycleTestSchema = `
CREATE TABLE IF NOT EXISTS key_lifecycle (
    key_id         TEXT PRIMARY KEY,
    owner          TEXT NOT NULL,
    acl            TEXT NOT NULL DEFAULT '[]',
    max_age_days   INTEGER NOT NULL DEFAULT 0 CHECK (max_age_days >= 0),
    rotated_at     TEXT NOT NULL,
    compromised_at TEXT,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);`

func newLifecycleTestDeps(t *testing.T) (*sql.DB, *keystore.SoftwareStore) {
	t.Helper()
	// busy_timeout: this pool is unbounded, and SQLite's default of 0 turns any
	// write overlap on a loaded machine into "database is locked (SQLITE_BUSY)".
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "lifecycle.db")+"?_busy_timeout=5000")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(keyLifecycleTestSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	store, err := keystore.NewSoftwareStore(t.TempDir(), []byte("lifecycle-test-passphrase-32-by!"))
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return db, store
}

func TestKeyACLBeyondAdminGate(t *testing.T) {
	db, store := newLifecycleTestDeps(t)
	if _, err := store.GenerateKey("guarded", keystore.ECDSAP256); err != nil {
		t.Fatalf("generate: %v", err)
	}
	m, err := NewKeyLifecycleManager(db, false, store)
	if err != nil {
		t.Fatalf("manager: %v", err)
	}

	// No policy: today's admin gate holds.
	if err := m.Authorize("guarded", "anyone", true); err != nil {
		t.Fatalf("admin on policy-less key refused: %v", err)
	}
	if err := m.Authorize("guarded", "anyone", false); err == nil {
		t.Fatal("non-admin on policy-less key must be refused")
	}

	if err := m.SetPolicy("guarded", "alice", []string{"bob"}, 0); err != nil {
		t.Fatalf("set policy: %v", err)
	}
	if err := m.Authorize("guarded", "alice", false); err != nil {
		t.Fatalf("owner refused: %v", err)
	}
	if err := m.Authorize("guarded", "bob", false); err != nil {
		t.Fatalf("ACL principal refused: %v", err)
	}
	// The acceptance's "beyond the global-admin gate": an admin NOT on the
	// key's ACL is refused once a policy exists.
	if err := m.Authorize("guarded", "root-admin", true); err == nil {
		t.Fatal("admin off the ACL must be refused on a policied key")
	}
	if err := m.Authorize("guarded", "mallory", false); err == nil {
		t.Fatal("stranger must be refused")
	}
}

func TestSetPolicyRefusesPhantomKey(t *testing.T) {
	db, store := newLifecycleTestDeps(t)
	m, _ := NewKeyLifecycleManager(db, false, store)
	if err := m.SetPolicy("no-such-key", "alice", nil, 30); err == nil {
		t.Fatal("policy for a key absent from the keystore must be refused")
	}
}

func TestRotationSweepRotatesOnlyOverdueKeys(t *testing.T) {
	db, store := newLifecycleTestDeps(t)
	for _, id := range []string{"old-key", "fresh-key", "unscheduled"} {
		if _, err := store.GenerateKey(id, keystore.ECDSAP256); err != nil {
			t.Fatalf("generate %s: %v", id, err)
		}
	}
	current := time.Now().UTC()
	m, err := NewKeyLifecycleManager(db, false, store, WithLifecycleClock(func() time.Time { return current }))
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	if err := m.SetPolicy("old-key", "alice", nil, 30); err != nil {
		t.Fatalf("policy: %v", err)
	}
	if err := m.SetPolicy("fresh-key", "alice", nil, 30); err != nil {
		t.Fatalf("policy: %v", err)
	}
	if err := m.SetPolicy("unscheduled", "alice", nil, 0); err != nil {
		t.Fatalf("policy: %v", err)
	}
	// Age old-key past its max age.
	stale := current.Add(-31 * 24 * time.Hour).Format(time.RFC3339)
	if _, err := db.Exec(`UPDATE key_lifecycle SET rotated_at = ? WHERE key_id = 'old-key'`, stale); err != nil {
		t.Fatalf("age key: %v", err)
	}

	report, err := m.RunRotationSweep(context.Background())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if len(report.Rotated) != 1 || report.Rotated[0] != "old-key" {
		t.Fatalf("expected exactly old-key rotated, got %v (errors %v)", report.Rotated, report.Errors)
	}
	// The stamp advanced: an immediate second sweep rotates nothing.
	report, err = m.RunRotationSweep(context.Background())
	if err != nil {
		t.Fatalf("second sweep: %v", err)
	}
	if len(report.Rotated) != 0 {
		t.Fatalf("second sweep must be a no-op, rotated %v", report.Rotated)
	}
}

type recordingRotator struct{ rotated []string }

func (r *recordingRotator) RotateCAKey(_ context.Context, id string, _ string) (CAKeyRotationResult, error) {
	r.rotated = append(r.rotated, id)
	return CAKeyRotationResult{ID: id}, nil
}

func TestSweepRoutesCABackedKeysThroughCARekey(t *testing.T) {
	db, store := newLifecycleTestDeps(t)
	if _, err := store.GenerateKey("ca-backing", keystore.ECDSAP256); err != nil {
		t.Fatalf("generate: %v", err)
	}
	caStore := ca.NewMemStore()
	if err := caStore.Save(&ca.CA{ID: "root-1", KeyID: "ca-backing", Status: "active"}); err != nil {
		t.Fatalf("save ca: %v", err)
	}
	rotator := &recordingRotator{}
	current := time.Now().UTC()
	m, _ := NewKeyLifecycleManager(db, false, store,
		WithLifecycleCARotation(rotator, caStore),
		WithLifecycleClock(func() time.Time { return current }))
	if err := m.SetPolicy("ca-backing", "alice", nil, 30); err != nil {
		t.Fatalf("policy: %v", err)
	}
	stale := current.Add(-40 * 24 * time.Hour).Format(time.RFC3339)
	if _, err := db.Exec(`UPDATE key_lifecycle SET rotated_at = ? WHERE key_id = 'ca-backing'`, stale); err != nil {
		t.Fatalf("age: %v", err)
	}

	report, err := m.RunRotationSweep(context.Background())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if len(rotator.rotated) != 1 || rotator.rotated[0] != "root-1" {
		t.Fatalf("CA-backed key must rotate via RotateCAKey(root-1), got %v (report %+v)", rotator.rotated, report)
	}
	// The raw keystore key was NOT rotated underneath the CA (G-35).
	if _, err := store.Signer("ca-backing"); err != nil {
		t.Fatalf("raw key must be untouched by CA re-key dispatch: %v", err)
	}
}

type lifecycleFakeCertProvider struct {
	CertificateProvider
	items   []CertificateItem
	flagged []string
}

func (f *lifecycleFakeCertProvider) ListCertificates(_ context.Context, q CertificateListQuery) (CertificateListResult, error) {
	var out []CertificateItem
	for _, it := range f.items {
		if q.CAID == "" || it.CAID == q.CAID {
			out = append(out, it)
		}
	}
	return CertificateListResult{Items: out, Total: len(out)}, nil
}

func (f *lifecycleFakeCertProvider) UpdateEstate(_ context.Context, fp string, u EstateUpdate) (CertificateItem, error) {
	// Enforce the real vocabulary: a permissive fake hid the production
	// rejection of "reissue_required".
	if u.RenewalStatus != "" && !validRenewalStatus(u.RenewalStatus) {
		return CertificateItem{}, errCertificateInvalid
	}
	if u.RenewalStatus == "reissue_required" {
		f.flagged = append(f.flagged, fp)
	}
	return CertificateItem{FingerprintSHA256: fp}, nil
}

type recordingReissuer struct {
	reissued       []string
	rotatedAtCalls *recordingRotator
	rotationsSeen  []int
}

func (r *recordingReissuer) ReissueCertificate(_ context.Context, fp string) error {
	r.reissued = append(r.reissued, fp)
	r.rotationsSeen = append(r.rotationsSeen, len(r.rotatedAtCalls.rotated))
	return nil
}

func TestCompromiseFlowForceRotatesThenReissuesAffectedCerts(t *testing.T) {
	db, store := newLifecycleTestDeps(t)
	if _, err := store.GenerateKey("burned", keystore.ECDSAP256); err != nil {
		t.Fatalf("generate: %v", err)
	}
	caStore := ca.NewMemStore()
	if err := caStore.Save(&ca.CA{ID: "issuing-1", KeyID: "burned", Status: "active"}); err != nil {
		t.Fatalf("save ca: %v", err)
	}
	rotator := &recordingRotator{}
	certs := &lifecycleFakeCertProvider{items: []CertificateItem{
		{FingerprintSHA256: "aaa", CAID: "issuing-1"},
		{FingerprintSHA256: "bbb", CAID: "issuing-1"},
		{FingerprintSHA256: "ccc", CAID: "other-ca"},
	}}
	reissuer := &recordingReissuer{rotatedAtCalls: rotator}
	m, _ := NewKeyLifecycleManager(db, false, store,
		WithLifecycleCARotation(rotator, caStore),
		WithLifecycleReissue(certs, reissuer))
	if err := m.SetPolicy("burned", "alice", nil, 0); err != nil {
		t.Fatalf("policy: %v", err)
	}

	report, err := m.MarkCompromised(context.Background(), "burned")
	if err != nil {
		t.Fatalf("compromise: %v", err)
	}
	if !report.Rotated || len(rotator.rotated) != 1 || rotator.rotated[0] != "issuing-1" {
		t.Fatalf("compromise must force-rotate via CA re-key, got %+v / %v", report, rotator.rotated)
	}
	if len(report.Affected) != 2 {
		t.Fatalf("affected set must be exactly the compromised CA's certs, got %v", report.Affected)
	}
	if len(reissuer.reissued) != 2 {
		t.Fatalf("both affected certs must be reissued, got %v", reissuer.reissued)
	}
	// Ordering: every reissue happened AFTER the rotation.
	for i, n := range reissuer.rotationsSeen {
		if n < 1 {
			t.Fatalf("reissue %d ran before the force-rotation — replacements would be signed by the compromised key", i)
		}
	}
	if len(certs.flagged) != 2 {
		t.Fatalf("affected certs must be flagged reissue_required, got %v", certs.flagged)
	}
	policy, found, err := m.GetPolicy("burned")
	if err != nil || !found {
		t.Fatalf("policy reload: %v %v", found, err)
	}
	if policy.CompromisedAt == nil {
		t.Fatal("compromise stamp missing")
	}

	// A compromised key is excluded from the routine sweep.
	if _, err := db.Exec(`UPDATE key_lifecycle SET max_age_days = 1, rotated_at = '2020-01-01T00:00:00Z' WHERE key_id = 'burned'`); err != nil {
		t.Fatalf("age: %v", err)
	}
	sweep, err := m.RunRotationSweep(context.Background())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if len(sweep.Rotated) != 0 {
		t.Fatalf("compromised keys must not be schedule-rotated, got %v", sweep.Rotated)
	}
}

func TestRotationSchedulerTicks(t *testing.T) {
	db, store := newLifecycleTestDeps(t)
	if _, err := store.GenerateKey("tick", keystore.ECDSAP256); err != nil {
		t.Fatalf("generate: %v", err)
	}
	current := time.Now().UTC()
	m, _ := NewKeyLifecycleManager(db, false, store, WithLifecycleClock(func() time.Time { return current }))
	if err := m.SetPolicy("tick", "alice", nil, 1); err != nil {
		t.Fatalf("policy: %v", err)
	}
	stale := current.Add(-48 * time.Hour).Format(time.RFC3339)
	if _, err := db.Exec(`UPDATE key_lifecycle SET rotated_at = ? WHERE key_id = 'tick'`, stale); err != nil {
		t.Fatalf("age: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.StartRotationScheduler(ctx, 20*time.Millisecond)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		policy, _, err := m.GetPolicy("tick")
		if err != nil {
			t.Fatalf("policy: %v", err)
		}
		if policy.RotatedAt.After(current.Add(-24 * time.Hour)) {
			return // scheduler swept and stamped
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("scheduler never rotated the overdue key")
}
