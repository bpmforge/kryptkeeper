// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
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

func TestSweepProposesCABackedKeyRotationInsteadOfRotating(t *testing.T) {
	db, store := newLifecycleTestDeps(t)
	if _, err := store.GenerateKey("ca-backing", keystore.ECDSAP256); err != nil {
		t.Fatalf("generate: %v", err)
	}
	caStore := ca.NewMemStore()
	if err := caStore.Save(&ca.CA{ID: "root-1", KeyID: "ca-backing", Status: "active"}); err != nil {
		t.Fatalf("save ca: %v", err)
	}
	rotator := &recordingRotator{}
	queue := newMemPendingStore()
	current := time.Now().UTC()
	m, _ := NewKeyLifecycleManager(db, false, store,
		WithLifecycleCARotation(rotator, caStore),
		WithLifecycleProposals(queue),
		WithLifecycleClock(func() time.Time { return current }))
	if err := m.SetPolicy("ca-backing", "alice", nil, 30); err != nil {
		t.Fatalf("policy: %v", err)
	}
	stale := current.Add(-40 * 24 * time.Hour).Format(time.RFC3339)
	if _, err := db.Exec(`UPDATE key_lifecycle SET rotated_at = ? WHERE key_id = 'ca-backing'`, stale); err != nil {
		t.Fatalf("age: %v", err)
	}

	for i := 0; i < 2; i++ { // the second sweep must not pile up a duplicate
		if _, err := m.RunRotationSweep(context.Background()); err != nil {
			t.Fatalf("sweep: %v", err)
		}
	}
	if len(rotator.rotated) != 0 {
		t.Fatalf("the scheduler must not rotate a CA key without approval, rotated %v", rotator.rotated)
	}
	if len(queue.actions) != 1 || queue.actions[0].ActionType != ActionScheduledCAKeyRotate || queue.actions[0].ProposedBy != lifecycleSchedulerPrincipal {
		t.Fatalf("want exactly one scheduled-rotation proposal, got %+v", queue.actions)
	}
	if p, _, _ := m.GetPolicy("ca-backing"); !p.RotatedAt.Before(current.Add(-30 * 24 * time.Hour)) {
		t.Fatal("an unapproved proposal must not reset the max-age clock")
	}

	// Approval carries it out (through RotateCAKey) and resets the clock.
	exec := NewScheduledCARotationExecutor(m)
	if _, err := exec(context.Background(), queue.actions[0], AuthPrincipal{ID: "bob", Role: "operator"}); err == nil {
		t.Fatal("a non-admin approver must be refused")
	}
	if _, err := exec(context.Background(), queue.actions[0], AuthPrincipal{ID: "bob", Role: "pki-admin"}); err != nil {
		t.Fatalf("executor: %v", err)
	}
	if len(rotator.rotated) != 1 || rotator.rotated[0] != "root-1" {
		t.Fatalf("approved rotation must re-key root-1, got %v", rotator.rotated)
	}
	if p, _, _ := m.GetPolicy("ca-backing"); p.RotatedAt.Before(current.Add(-time.Hour)) {
		t.Fatal("approved rotation must stamp rotated_at")
	}
}

func TestSweepSkipsCABackedKeyWithoutApprovalQueue(t *testing.T) {
	db, store := newLifecycleTestDeps(t)
	if _, err := store.GenerateKey("ca-backing", keystore.ECDSAP256); err != nil {
		t.Fatal(err)
	}
	caStore := ca.NewMemStore()
	_ = caStore.Save(&ca.CA{ID: "root-1", KeyID: "ca-backing", Status: "active"})
	rotator := &recordingRotator{}
	current := time.Now().UTC()
	m, _ := NewKeyLifecycleManager(db, false, store, WithLifecycleCARotation(rotator, caStore), WithLifecycleClock(func() time.Time { return current }))
	_ = m.SetPolicy("ca-backing", "alice", nil, 30)
	_, _ = db.Exec(`UPDATE key_lifecycle SET rotated_at = ? WHERE key_id = 'ca-backing'`, current.Add(-40*24*time.Hour).Format(time.RFC3339))
	report, err := m.RunRotationSweep(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rotator.rotated) != 0 || report.Errors["ca-backing"] == "" {
		t.Fatalf("with no queue the CA key must stay unrotated and reported: %+v rotated=%v", report, rotator.rotated)
	}
}

// memPendingStore is an in-memory PendingActionStore for the sweep tests.
type memPendingStore struct {
	PendingActionStore
	actions []PendingAction
}

func newMemPendingStore() *memPendingStore { return &memPendingStore{} }

func (s *memPendingStore) Create(_ context.Context, a PendingAction) (PendingAction, error) {
	a.ID = fmt.Sprintf("act-%d", len(s.actions)+1)
	a.Status = "pending"
	s.actions = append(s.actions, a)
	return a, nil
}

func (s *memPendingStore) List(_ context.Context, status string) ([]PendingAction, error) {
	var out []PendingAction
	for _, a := range s.actions {
		if a.Status == status {
			out = append(out, a)
		}
	}
	return out, nil
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

// --- W23-38: policy API, ACL enforcement, dual-controlled compromise ---

// orderLog is shared by the fakes so a test can assert the cross-collaborator
// call order.
type orderLog struct{ calls []string }

type orderRotator struct {
	log *orderLog
	err error
}

func (r *orderRotator) RotateCAKey(_ context.Context, id string, _ string) (CAKeyRotationResult, error) {
	if r.err != nil {
		return CAKeyRotationResult{}, r.err
	}
	r.log.calls = append(r.log.calls, "rotate")
	return CAKeyRotationResult{ID: id}, nil
}

type orderCerts struct {
	lifecycleFakeCertProvider
	log     *orderLog
	revoked []string
	// inventoryOnly names fingerprints whose revoke only reaches the inventory.
	inventoryOnly map[string]bool
}

func (c *orderCerts) RevokeCertificate(_ context.Context, fp string, req CertificateRevokeRequest) (CertificateRevokeResult, error) {
	if req.ReasonCode != 1 {
		return CertificateRevokeResult{}, fmt.Errorf("want reason keyCompromise(1), got %d", req.ReasonCode)
	}
	c.log.calls = append(c.log.calls, "revoke:"+fp)
	c.revoked = append(c.revoked, fp)
	scope := RevocationScopeCA
	if c.inventoryOnly[fp] {
		scope = RevocationScopeInventoryOnly
	}
	return CertificateRevokeResult{FingerprintSHA256: fp, RevocationScope: scope}, nil
}

func (c *orderCerts) UpdateEstate(ctx context.Context, fp string, u EstateUpdate) (CertificateItem, error) {
	c.log.calls = append(c.log.calls, "flag:"+fp)
	return c.lifecycleFakeCertProvider.UpdateEstate(ctx, fp, u)
}

type orderReissuer struct{ log *orderLog }

func (r *orderReissuer) ReissueCertificate(_ context.Context, fp string) error {
	r.log.calls = append(r.log.calls, "reissue:"+fp)
	return nil
}

func compromiseFixture(t *testing.T, rotateErr error) (*KeyLifecycleManager, *sql.DB, *orderLog, *orderCerts) {
	t.Helper()
	db, store := newLifecycleTestDeps(t)
	if _, err := store.GenerateKey("burned", keystore.ECDSAP256); err != nil {
		t.Fatal(err)
	}
	caStore := ca.NewMemStore()
	if err := caStore.Save(&ca.CA{ID: "issuing-1", KeyID: "burned", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	log := &orderLog{}
	certs := &orderCerts{log: log, lifecycleFakeCertProvider: lifecycleFakeCertProvider{items: []CertificateItem{
		{FingerprintSHA256: "aaa", CAID: "issuing-1"},
		{FingerprintSHA256: "bbb", CAID: "issuing-1"},
	}}}
	m, err := NewKeyLifecycleManager(db, false, store,
		WithLifecycleCARotation(&orderRotator{log: log, err: rotateErr}, caStore),
		WithLifecycleReissue(certs, &orderReissuer{log: log}),
		WithLifecycleRevoker(certs))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SetPolicy("burned", "alice", nil, 0); err != nil {
		t.Fatal(err)
	}
	return m, db, log, certs
}

func TestCompromiseOrder(t *testing.T) {
	m, _, log, certs := compromiseFixture(t, nil)
	report, err := m.MarkCompromised(context.Background(), "burned")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(report.Steps, ","); got != "rotate,flag,revoke,reissue" {
		t.Fatalf("steps = %s", got)
	}
	if len(report.Revoked) != 2 || len(certs.revoked) != 2 {
		t.Fatalf("both affected certs must be revoked: %+v", report)
	}
	// The recorded calls must have rotation first and every revoke before
	// any reissue.
	if log.calls[0] != "rotate" {
		t.Fatalf("rotation must come first: %v", log.calls)
	}
	lastRevoke, firstReissue := -1, len(log.calls)
	for i, c := range log.calls {
		if strings.HasPrefix(c, "revoke:") {
			lastRevoke = i
		}
		if strings.HasPrefix(c, "reissue:") && i < firstReissue {
			firstReissue = i
		}
	}
	if lastRevoke < 0 || lastRevoke > firstReissue {
		t.Fatalf("revokes must precede reissues: %v", log.calls)
	}
	if p, _, _ := m.GetPolicy("burned"); p.CompromisedAt == nil {
		t.Fatal("compromised_at must be stamped")
	}
}

func TestCompromiseRotateFailureHasNoSideEffects(t *testing.T) {
	m, db, log, certs := compromiseFixture(t, errors.New("hsm offline"))
	if _, err := m.MarkCompromised(context.Background(), "burned"); err == nil {
		t.Fatal("a failed rotation must fail the flow")
	}
	var stamped sql.NullString
	if err := db.QueryRow(`SELECT compromised_at FROM key_lifecycle WHERE key_id = 'burned'`).Scan(&stamped); err != nil {
		t.Fatal(err)
	}
	if stamped.Valid {
		t.Fatal("compromised_at must stay NULL when the rotation fails")
	}
	if len(log.calls) != 0 || len(certs.revoked) != 0 || len(certs.flagged) != 0 {
		t.Fatalf("no revoke/flag/reissue after a failed rotation: calls=%v flagged=%v", log.calls, certs.flagged)
	}
}

type lifecycleHTTPEnv struct {
	*importEnv
	m    *KeyLifecycleManager
	log  *orderLog
	db   *sql.DB
	mux  *http.ServeMux
	exec map[string]ActionExecutor
}

func newLifecycleHTTPEnv(t *testing.T, dualControl string) *lifecycleHTTPEnv {
	t.Helper()
	e := newImportEnv(t, dualControl)
	db, _ := newLifecycleTestDeps(t)
	log := &orderLog{}
	caStore := ca.NewMemStore()
	_ = caStore.Save(&ca.CA{ID: "issuing-1", KeyID: "burned", Status: "active"})
	certs := &orderCerts{log: log, lifecycleFakeCertProvider: lifecycleFakeCertProvider{items: []CertificateItem{{FingerprintSHA256: "aaa", CAID: "issuing-1"}}}}
	m, err := NewKeyLifecycleManager(db, false, e.keys,
		WithLifecycleCARotation(&orderRotator{log: log}, caStore),
		WithLifecycleReissue(certs, &orderReissuer{log: log}),
		WithLifecycleRevoker(certs))
	if err != nil {
		t.Fatal(err)
	}
	SetActiveKeyLifecycle(m)
	t.Cleanup(func() { SetActiveKeyLifecycle(nil) })
	for _, id := range []string{"burned", "plain"} {
		if _, err := e.keys.GenerateKey(id, keystore.ECDSAP256); err != nil {
			t.Fatal(err)
		}
	}
	exec := map[string]ActionExecutor{ActionKeyCompromise: NewKeyCompromiseExecutor(m, e.audit)}
	mux := http.NewServeMux()
	registerKeyHandlers(mux, e.auth, e.keys, e.audit, "")
	registerPendingActionHandlers(mux, e.auth, NewFileCertificateProviderFromEnv(), NewPendingActionStoreFromEnv(), e.audit, exec, e.keys)
	e.mux = mux
	return &lifecycleHTTPEnv{importEnv: e, m: m, log: log, db: db, mux: mux, exec: exec}
}

func TestPolicyAPIRoundTrip(t *testing.T) {
	e := newLifecycleHTTPEnv(t, "unset")
	rec := e.do(e.alice, http.MethodPut, "/api/v1/keys/plain/policy", map[string]any{"owner": "alice", "acl": []string{"bob"}, "max_age_days": 90})
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT: %d %s", rec.Code, rec.Body.String())
	}
	rec = e.do(e.bob, http.MethodGet, "/api/v1/keys/plain/policy", nil)
	var got struct {
		Data KeyPolicy `json:"data"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil {
		t.Fatalf("GET: %d %s", rec.Code, rec.Body.String())
	}
	if got.Data.Owner != "alice" || len(got.Data.ACL) != 1 || got.Data.ACL[0] != "bob" || got.Data.MaxAgeDays != 90 {
		t.Fatalf("round trip lost data: %+v", got.Data)
	}
	if !e.audited("key.policy_set", AuditOutcomeSuccess) {
		t.Fatal("policy change must be audited")
	}
	if rec := e.do(e.alice, http.MethodPut, "/api/v1/keys/plain/policy", map[string]any{"owner": "", "max_age_days": 1}); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty owner: want 400, got %d", rec.Code)
	}
	if rec := e.do(e.alice, http.MethodPut, "/api/v1/keys/plain/policy", map[string]any{"owner": "a", "max_age_days": -1}); rec.Code != http.StatusBadRequest {
		t.Fatalf("negative max age: want 400, got %d", rec.Code)
	}
	if rec := e.do(e.alice, http.MethodPut, "/api/v1/keys/ghost/policy", map[string]any{"owner": "a"}); rec.Code != http.StatusNotFound {
		t.Fatalf("missing key: want 404, got %d", rec.Code)
	}
	if rec := e.do(e.alice, http.MethodGet, "/api/v1/keys/burned/policy", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("no policy: want 404, got %d", rec.Code)
	}
}

func TestNonACLAdminRefusedOnPoliciedKey(t *testing.T) {
	e := newLifecycleHTTPEnv(t, "unset")
	if err := e.m.SetPolicy("plain", "alice", nil, 0); err != nil {
		t.Fatal(err)
	}
	// bob is a pki-admin but not on the key's ACL.
	for _, c := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/keys/plain/rotate"},
		{http.MethodDelete, "/api/v1/keys/plain"},
		{http.MethodPost, "/api/v1/keys/plain/export"},
	} {
		rec := e.do(e.bob, c.method, c.path, map[string]any{"passphrase": "x"})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s %s as non-ACL admin: want 403, got %d: %s", c.method, c.path, rec.Code, rec.Body.String())
		}
	}
	if !e.audited("key.op", AuditOutcomeDenied) {
		t.Fatal("refusal must be audited")
	}
	// The owner passes the ACL and reaches the dual-control gate.
	if rec := e.do(e.alice, http.MethodPost, "/api/v1/keys/plain/rotate", map[string]any{}); rec.Code != http.StatusAccepted {
		t.Fatalf("owner rotate: want 202 (proposal), got %d: %s", rec.Code, rec.Body.String())
	}
	// A key with no policy keeps today's admin-only behaviour.
	if rec := e.do(e.bob, http.MethodPost, "/api/v1/keys/burned/rotate", map[string]any{}); rec.Code != http.StatusAccepted {
		t.Fatalf("unpolicied key: want 202, got %d", rec.Code)
	}
}

// An unreachable policy store must still refuse the op (fail closed) but as
// 503, not a 403 authz denial, and without echoing the driver error.
func TestKeyOpPolicyStoreDownFailsClosedAs503(t *testing.T) {
	e := newLifecycleHTTPEnv(t, "unset")
	e.m.db.Close()
	for _, c := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/keys/burned/rotate"},
		{http.MethodDelete, "/api/v1/keys/burned"},
		{http.MethodPost, "/api/v1/keys/burned/export"},
	} {
		rec := e.do(e.alice, c.method, c.path, map[string]any{"passphrase": "x"})
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s %s with policy store down: want 503, got %d: %s", c.method, c.path, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "sql:") {
			t.Fatalf("driver error leaked to client: %s", rec.Body.String())
		}
	}
	if !e.audited("key.op", AuditOutcomeFailure) {
		t.Fatal("outage refusal must be audited as a failure")
	}
}

func TestCompromiseProposesOnly(t *testing.T) {
	e := newLifecycleHTTPEnv(t, "false") // the env bypass must not apply
	if rec := e.do(e.alice, http.MethodPost, "/api/v1/keys/burned/compromise", nil); rec.Code != http.StatusConflict {
		t.Fatalf("no policy: want 409, got %d: %s", rec.Code, rec.Body.String())
	}
	if err := e.m.SetPolicy("burned", "alice", []string{"bob"}, 0); err != nil {
		t.Fatal(err)
	}
	rec := e.do(e.alice, http.MethodPost, "/api/v1/keys/burned/compromise", nil)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("want 202, got %d: %s", rec.Code, rec.Body.String())
	}
	act := actionID(t, rec)
	if p, _, _ := e.m.GetPolicy("burned"); p.CompromisedAt != nil || len(e.log.calls) != 0 {
		t.Fatalf("a proposal must not run anything: %+v %v", p, e.log.calls)
	}
	if !e.audited("key.compromise", AuditOutcomeProposed) {
		t.Fatal("proposal must be audited")
	}
	if rec := e.do(e.alice, http.MethodPost, "/api/v1/pending-actions/"+act+"/approve", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("self-approval: want 403, got %d", rec.Code)
	}
	if rec := e.do(e.bob, http.MethodPost, "/api/v1/pending-actions/"+act+"/approve", nil); rec.Code != http.StatusOK {
		t.Fatalf("second admin approve: %d %s", rec.Code, rec.Body.String())
	}
	if p, _, _ := e.m.GetPolicy("burned"); p.CompromisedAt == nil || e.log.calls[0] != "rotate" {
		t.Fatalf("approval must run the flow: %+v %v", p, e.log.calls)
	}
	if !e.audited("key.compromise", AuditOutcomeExecuted) {
		t.Fatal("execution must be audited")
	}
}

func TestSweepRotatesOverdueKeyInRunningHub(t *testing.T) {
	db, store := newLifecycleTestDeps(t)
	if _, err := store.GenerateKey("aging", keystore.ECDSAP256); err != nil {
		t.Fatal(err)
	}
	skew := time.Duration(0)
	m, _ := NewKeyLifecycleManager(db, false, store, WithLifecycleClock(func() time.Time { return time.Now().Add(skew) }))
	if err := m.SetPolicy("aging", "alice", nil, 1); err != nil {
		t.Fatal(err)
	}
	skew = 48 * time.Hour
	report, err := m.RunRotationSweep(context.Background())
	if err != nil || len(report.Rotated) != 1 || report.Rotated[0] != "aging" {
		t.Fatalf("one sweep must rotate the overdue key: %+v %v", report, err)
	}
}

// A certificate the compromise flow revoked keeps renewal_status "revoked":
// flagging it reissue_required overwrote that in the inventory.
func TestCompromiseDoesNotFlagRevokedCerts(t *testing.T) {
	m, _, log, certs := compromiseFixture(t, nil)
	report, err := m.MarkCompromised(context.Background(), "burned")
	if err != nil {
		t.Fatal(err)
	}
	if len(certs.revoked) != 2 {
		t.Fatalf("both certs must be revoked: %v", certs.revoked)
	}
	if len(certs.flagged) != 0 {
		t.Fatalf("revoked certs must not be flagged reissue_required: %v (calls %v)", certs.flagged, log.calls)
	}
	for _, c := range log.calls {
		if strings.HasPrefix(c, "flag:") {
			t.Fatalf("UpdateEstate must not run for revoked certs: %v", log.calls)
		}
	}
	if len(report.Affected) != 2 {
		t.Fatalf("revoked certs are still affected and re-issued: %v", report.Affected)
	}
}

// failingRevoker refuses one fingerprint, leaving that cert un-revoked.
type failingRevoker struct {
	*orderCerts
	failFP string
}

func (r failingRevoker) RevokeCertificate(ctx context.Context, fp string, req CertificateRevokeRequest) (CertificateRevokeResult, error) {
	if fp == r.failFP {
		return CertificateRevokeResult{}, errors.New("revoke backend down")
	}
	return r.orderCerts.RevokeCertificate(ctx, fp, req)
}

// Only not-yet-revoked dependents get reissue_required; certs revoked before
// the compromise are skipped too.
func TestCompromiseFlagsOnlyUnrevokedDependents(t *testing.T) {
	db, store := newLifecycleTestDeps(t)
	if _, err := store.GenerateKey("burned", keystore.ECDSAP256); err != nil {
		t.Fatal(err)
	}
	caStore := ca.NewMemStore()
	if err := caStore.Save(&ca.CA{ID: "issuing-1", KeyID: "burned", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	earlier := "2026-01-01T00:00:00Z"
	log := &orderLog{}
	certs := &orderCerts{log: log, lifecycleFakeCertProvider: lifecycleFakeCertProvider{items: []CertificateItem{
		{FingerprintSHA256: "revoked-now", CAID: "issuing-1"},
		{FingerprintSHA256: "revoke-fails", CAID: "issuing-1"},
		{FingerprintSHA256: "revoked-before", CAID: "issuing-1", RevokedAt: &earlier, RenewalStatus: "revoked"},
	}}}
	m, err := NewKeyLifecycleManager(db, false, store,
		WithLifecycleCARotation(&orderRotator{log: log}, caStore),
		WithLifecycleReissue(certs, &orderReissuer{log: log}),
		WithLifecycleRevoker(failingRevoker{orderCerts: certs, failFP: "revoke-fails"}))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SetPolicy("burned", "alice", nil, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := m.MarkCompromised(context.Background(), "burned"); err != nil {
		t.Fatal(err)
	}
	if len(certs.flagged) != 1 || certs.flagged[0] != "revoke-fails" {
		t.Fatalf("only the un-revoked dependent may be flagged, got %v", certs.flagged)
	}
}

// W23-38 review: the sweep runs on the HA lease holder only. Plain keys rotate
// directly, so two replicas sweeping at once would rotate the same key twice.
func TestSweepTickNonLeaderDoesNotRotate(t *testing.T) {
	db, store := newLifecycleTestDeps(t)
	if _, err := store.GenerateKey("plain", keystore.ECDSAP256); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	leader := newTestHACoordinatorAt(t, db, "replica-leader", now)
	follower := newTestHACoordinatorAt(t, db, "replica-follower", now)
	if ok, err := leader.TryAcquire(context.Background(), haLockKeyRotationSweep, time.Hour); err != nil || !ok {
		t.Fatalf("leader acquire: %v %v", ok, err)
	}

	age := func(m *KeyLifecycleManager) {
		t.Helper()
		if err := m.SetPolicy("plain", "alice", nil, 1); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`UPDATE key_lifecycle SET rotated_at = ? WHERE key_id = 'plain'`, now.Add(-48*time.Hour).Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
	}
	rotatedAt := func(m *KeyLifecycleManager) time.Time {
		t.Helper()
		p, _, err := m.GetPolicy("plain")
		if err != nil {
			t.Fatal(err)
		}
		return p.RotatedAt
	}
	clock := WithLifecycleClock(func() time.Time { return now })

	followerMgr, _ := NewKeyLifecycleManager(db, false, store, clock, WithLifecycleLeader(follower))
	age(followerMgr)
	followerMgr.sweepTick(context.Background(), time.Hour)
	if got := rotatedAt(followerMgr); !got.Before(now.Add(-24 * time.Hour)) {
		t.Fatalf("a non-leader must not rotate: rotated_at advanced to %v", got)
	}

	leaderMgr, _ := NewKeyLifecycleManager(db, false, store, clock, WithLifecycleLeader(leader))
	leaderMgr.sweepTick(context.Background(), time.Hour)
	if got := rotatedAt(leaderMgr); got.Before(now.Add(-time.Minute)) {
		t.Fatalf("the lease holder must rotate: rotated_at still %v", got)
	}
}

// A lease check that errors fails closed: skip the tick rather than risk a
// duplicate rotation.
func TestSweepTickLeaseErrorSkips(t *testing.T) {
	db, store := newLifecycleTestDeps(t)
	if _, err := store.GenerateKey("plain", keystore.ECDSAP256); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	// No ha_scheduler_locks table: TryAcquire errors.
	broken := &HACoordinator{db: db, ph: sqlitePlaceholder, replicaID: "replica-x", now: func() time.Time { return now }}
	m, _ := NewKeyLifecycleManager(db, false, store, WithLifecycleClock(func() time.Time { return now }), WithLifecycleLeader(broken))
	if err := m.SetPolicy("plain", "alice", nil, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE key_lifecycle SET rotated_at = ? WHERE key_id = 'plain'`, now.Add(-48*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	m.sweepTick(context.Background(), time.Hour)
	if p, _, _ := m.GetPolicy("plain"); !p.RotatedAt.Before(now.Add(-24 * time.Hour)) {
		t.Fatal("a lease error must skip the sweep")
	}
}

// S-07: a sweep must not let an inventory-only revocation look like a real one.
func TestCompromiseReportsInventoryOnlyRevocations(t *testing.T) {
	db, store := newLifecycleTestDeps(t)
	if _, err := store.GenerateKey("burned", keystore.ECDSAP256); err != nil {
		t.Fatal(err)
	}
	caStore := ca.NewMemStore()
	if err := caStore.Save(&ca.CA{ID: "issuing-1", KeyID: "burned", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	log := &orderLog{}
	certs := &orderCerts{log: log, lifecycleFakeCertProvider: lifecycleFakeCertProvider{items: []CertificateItem{
		{FingerprintSHA256: "hub-issued", CAID: "issuing-1"},
		{FingerprintSHA256: "imported", CAID: "issuing-1"},
	}}, inventoryOnly: map[string]bool{"imported": true}}
	m, err := NewKeyLifecycleManager(db, false, store,
		WithLifecycleCARotation(&orderRotator{log: log}, caStore),
		WithLifecycleReissue(certs, &orderReissuer{log: log}),
		WithLifecycleRevoker(certs))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SetPolicy("burned", "alice", nil, 0); err != nil {
		t.Fatal(err)
	}
	report, err := m.MarkCompromised(context.Background(), "burned")
	if err != nil {
		t.Fatal(err)
	}
	if len(report.InventoryOnly) != 1 || report.InventoryOnly[0] != "imported" {
		t.Fatalf("inventory_only = %v, want [imported]", report.InventoryOnly)
	}
	if len(report.Revoked) != 2 {
		t.Fatalf("revoked = %v", report.Revoked)
	}
}
