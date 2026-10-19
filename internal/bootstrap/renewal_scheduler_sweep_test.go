// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"encoding/pem"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"kryptkeeper/internal/agentinstall"
)

// S-17 sweep tests: the scheduler EXECUTES renewals for opted-in ssh-mode
// targets through the W5-13 engine, and stays notify-only for everyone else.
// Predecessors are issued through the production path (S-66 lesson).

func newSweepTestTargetStore(t *testing.T) ManagedTargetStore {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "sweep-targets.db"))
	if err != nil {
		t.Fatalf("open targets db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	store := &sqliteManagedTargetStore{db: db}
	if err := store.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("ensure schema: %v", err)
	}
	return store
}

func sweepTarget(autoRenew bool) ManagedTarget {
	now := time.Now().UTC().Format(time.RFC3339)
	return ManagedTarget{
		ID: "tgt-sweep", Name: "sweep-web", Host: "sweep.example.com",
		DiscoveryMode: "none", InstallMode: "ssh", RenewalMethod: "manual",
		// 100-day threshold makes a fresh 90-day cert an immediate candidate.
		RenewalThresholdDays: 100,
		CredentialRef:        "cred-1",
		InstallServerType:    "nginx",
		InstallCertPath:      "/etc/nginx/tls/sweep.crt",
		InstallKeyPath:       "/etc/nginx/tls/sweep.key",
		AutoRenew:            autoRenew,
		AutoRenewSetBy:       "sweep-test-admin",
		Tenant:               "default",
		CreatedAt:            now, UpdatedAt: now,
	}
}

// The store round-trips the new install-profile columns on both the
// migration-shaped schema and the EnsureSchema self-heal path.
func TestManagedTargetStoreRoundTripsInstallProfile(t *testing.T) {
	store := newSweepTestTargetStore(t)
	ctx := context.Background()

	if _, err := store.Create(ctx, sweepTarget(true)); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := store.Get(ctx, "tgt-sweep")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !got.AutoRenew || got.InstallServerType != "nginx" ||
		got.InstallCertPath != "/etc/nginx/tls/sweep.crt" ||
		got.InstallKeyPath != "/etc/nginx/tls/sweep.key" {
		t.Fatalf("install profile lost in round-trip: %+v", got)
	}

	off := false
	updated, err := store.Update(ctx, "tgt-sweep", ManagedTargetUpdate{AutoRenew: &off})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.AutoRenew {
		t.Fatal("PATCH auto_renew=false did not stick")
	}
	if updated.InstallCertPath != "/etc/nginx/tls/sweep.crt" {
		t.Fatal("PATCH of one field clobbered the install profile")
	}
}

func newSweepScheduler(t *testing.T, provider CertificateProvider, targets ManagedTargetStore, engine *RenewalExecutor) *RenewalScheduler {
	t.Helper()
	// Sweep failures land in the package-level failure queue; isolate each test.
	resetRenewalRetryStateForTest()
	t.Cleanup(resetRenewalRetryStateForTest)
	s := &RenewalScheduler{
		certProvider:  provider,
		auditProvider: stubAuditProvider{},
		thresholdDays: 30,
		pollInterval:  time.Hour,
		cooldown:      time.Hour,
		targetStore:   targets,
		stop:          make(chan struct{}),
		// A fresh store has not run the backfill, so the first tick binds the
		// CN/SAN == host matches these fixtures are built around.
		bindingStore: newFreshBindingStore(t),
	}
	return s.WithRenewalExecutor(engine)
}

func TestRenewalSweepExecutesOptedInTarget(t *testing.T) {
	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	ctx := context.Background()

	issued, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       getFirstCAID(t, engine),
		CSRPEM:     generateTestCSRPEM(t, "sweep.example.com", "sweep.example.com"),
		TemplateID: "file-backed-default",
		TeamID:     "team-sweep",
	})
	if err != nil {
		t.Fatalf("issue predecessor: %v", err)
	}
	predecessorFP := issued.CertificateItem.FingerprintSHA256

	targets := newSweepTestTargetStore(t)
	if _, err := targets.Create(ctx, sweepTarget(true)); err != nil {
		t.Fatalf("create target: %v", err)
	}

	fake := &renewalFakeExecutor{files: map[string][]byte{}}
	exec := newRenewalTestEngine(t, provider, fake, testSSHCredentialJSON(t))
	// The sweep target's paths differ from the engine-test default; point the
	// verifier at the sweep's cert path.
	exec.verifier = func(_ context.Context, _ string) (string, error) {
		block, _ := pem.Decode(fake.files["/etc/nginx/tls/sweep.crt"])
		if block == nil {
			return "", contextErr("nothing installed")
		}
		return agentinstall.FingerprintSHA256(block.Bytes), nil
	}

	sched := newSweepScheduler(t, provider, targets, exec)
	sched.runScan()

	st := sched.Status()
	if st.LastAutoRenewTriggers != 1 {
		t.Fatalf("expected 1 auto-renew trigger, got %+v", st)
	}

	// The predecessor now has a successor, issued by the sweep.
	after, _, err := provider.GetCertificate(ctx, predecessorFP)
	if err != nil {
		t.Fatalf("get predecessor: %v", err)
	}
	if after.SuccessorFP == nil {
		t.Fatal("sweep claimed a trigger but no successor exists")
	}
	// And the target actually received the successor's bytes.
	block, _ := pem.Decode(fake.files["/etc/nginx/tls/sweep.crt"])
	if block == nil {
		t.Fatal("sweep did not install onto the target")
	}
	if got := agentinstall.FingerprintSHA256(block.Bytes); got != *after.SuccessorFP {
		t.Fatalf("installed %s but successor is %s", got, *after.SuccessorFP)
	}
}

// Without the explicit opt-in the sweep must not execute — same cert, same
// profile, auto_renew=false. This is the red-check surface for the gate.
func TestRenewalSweepSkipsWithoutOptIn(t *testing.T) {
	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	ctx := context.Background()

	issued, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       getFirstCAID(t, engine),
		CSRPEM:     generateTestCSRPEM(t, "sweep.example.com", "sweep.example.com"),
		TemplateID: "file-backed-default",
		TeamID:     "team-sweep-off",
	})
	if err != nil {
		t.Fatalf("issue predecessor: %v", err)
	}

	targets := newSweepTestTargetStore(t)
	if _, err := targets.Create(ctx, sweepTarget(false)); err != nil {
		t.Fatalf("create target: %v", err)
	}

	fake := &renewalFakeExecutor{files: map[string][]byte{}}
	sched := newSweepScheduler(t, provider, targets, newRenewalTestEngine(t, provider, fake, testSSHCredentialJSON(t)))
	sched.runScan()

	if st := sched.Status(); st.LastAutoRenewTriggers != 0 {
		t.Fatalf("sweep executed a non-opted-in target: %+v", st)
	}
	after, _, err := provider.GetCertificate(ctx, issued.CertificateItem.FingerprintSHA256)
	if err != nil {
		t.Fatalf("get predecessor: %v", err)
	}
	if after.SuccessorFP != nil {
		t.Fatal("a successor was minted without opt-in")
	}
}

// A failing install counts as zero triggers and leaves the candidate on the
// notify path — the sweep must never hide a partial outcome as success.
func TestRenewalSweepPartialInstallIsNotATrigger(t *testing.T) {
	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	ctx := context.Background()

	if _, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       getFirstCAID(t, engine),
		CSRPEM:     generateTestCSRPEM(t, "sweep.example.com", "sweep.example.com"),
		TemplateID: "file-backed-default",
		TeamID:     "team-sweep-partial",
	}); err != nil {
		t.Fatalf("issue predecessor: %v", err)
	}

	targets := newSweepTestTargetStore(t)
	if _, err := targets.Create(ctx, sweepTarget(true)); err != nil {
		t.Fatalf("create target: %v", err)
	}

	fake := &renewalFakeExecutor{files: map[string][]byte{}, failCommand: "nginx"}
	sched := newSweepScheduler(t, provider, targets, newRenewalTestEngine(t, provider, fake, testSSHCredentialJSON(t)))
	sched.runScan()

	if st := sched.Status(); st.LastAutoRenewTriggers != 0 {
		t.Fatalf("a config-test failure must not count as a trigger: %+v", st)
	}
}

// contextErr is a tiny error helper (errors.New shadow-free in this file).
type contextErr string

func (e contextErr) Error() string { return string(e) }
