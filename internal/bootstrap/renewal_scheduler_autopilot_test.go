// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"testing"
	"time"
)

// A failed or partial auto-renew must be auditable AS a failure, with the
// install outcome in the record: an append-only trail that says "success"
// for a rolled-back install cannot be reconstructed into what happened.
func TestRenewalSweepAuditsFailureAsFailure(t *testing.T) {
	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	ctx := context.Background()

	if _, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       getFirstCAID(t, engine),
		CSRPEM:     generateTestCSRPEM(t, "sweep.example.com", "sweep.example.com"),
		TemplateID: "file-backed-default",
		TeamID:     "team-sweep-audit",
	}); err != nil {
		t.Fatalf("issue predecessor: %v", err)
	}
	targets := newSweepTestTargetStore(t)
	if _, err := targets.Create(ctx, sweepTarget(true)); err != nil {
		t.Fatalf("create target: %v", err)
	}

	fake := &renewalFakeExecutor{files: map[string][]byte{}, failCommand: "nginx"}
	sched := newSweepScheduler(t, provider, targets, newRenewalTestEngine(t, provider, fake, testSSHCredentialJSON(t)))
	rec := &recordingAuditProvider{}
	sched.auditProvider = rec
	sched.runScan()

	var found bool
	for _, e := range rec.entries {
		if e.Action != "certificate.renew_execute_partial" && e.Action != "certificate.renew_execute_failed" {
			continue
		}
		found = true
		if e.Outcome != "failure" {
			t.Fatalf("%s recorded outcome %q, want failure", e.Action, e.Outcome)
		}
		if e.ChangeSummary == "" {
			t.Fatalf("%s carries no detail of what failed", e.Action)
		}
	}
	if !found {
		t.Fatalf("no failed/partial renew audit entry among %+v", rec.entries)
	}
}

// "Execution failed: fall through so the owner still gets the expiry
// reminder -- an armed sweep must never LOSE alerts." The attempt itself burns
// the cooldown, so the fall-through reminder must not be suppressed by the
// cooldown the failed attempt just recorded (found live: a rolled-back
// auto-renew produced no owner notification at all).
func TestRenewalSweepFailedAttemptStillNotifiesOwner(t *testing.T) {
	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	ctx := context.Background()

	issued, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       getFirstCAID(t, engine),
		CSRPEM:     generateTestCSRPEM(t, "sweep.example.com", "sweep.example.com"),
		TemplateID: "file-backed-default",
		TeamID:     "team-sweep-notify",
	})
	if err != nil {
		t.Fatalf("issue predecessor: %v", err)
	}
	if _, err := provider.UpdateOwnership(ctx, issued.CertificateItem.FingerprintSHA256, CertificateOwnershipRequest{OwnerEmail: "owner@example.test"}); err != nil {
		t.Fatalf("set owner: %v", err)
	}
	targets := newSweepTestTargetStore(t)
	if _, err := targets.Create(ctx, sweepTarget(true)); err != nil {
		t.Fatalf("create target: %v", err)
	}

	fake := &renewalFakeExecutor{files: map[string][]byte{}, failCommand: "nginx"}
	sched := newSweepScheduler(t, provider, targets, newRenewalTestEngine(t, provider, fake, testSSHCredentialJSON(t)))
	notif := &recordingNotificationProvider{}
	sched.notifProvider = notif
	sched.cooldownStore = newFreshRenewalAlertCooldownStore(t)
	sched.runScan()

	if len(notif.sent) != 1 || notif.sent[0] != "owner@example.test" {
		t.Fatalf("owner notifications after a failed auto-renew = %v, want exactly one to owner@example.test", notif.sent)
	}
	// The burned cooldown still protects the next tick from a second attempt
	// and a second reminder.
	sched.runScan()
	if len(notif.sent) != 1 {
		t.Fatalf("cooldown did not hold on the next tick: %v", notif.sent)
	}
}

// RENEWAL_POLL_MINUTES gives a sub-hour cadence, and the per-tick config
// resolution must not truncate it back to whole hours.
func TestRenewalSchedulerPollMinutesEnv(t *testing.T) {
	t.Setenv("RENEWAL_POLL_HOURS", "")
	t.Setenv("RENEWAL_POLL_MINUTES", "2")
	s := NewRenewalSchedulerFromEnv(&reportCertProvider{}, nil, stubAuditProvider{})
	s.configStore = newFreshConfigStore(t, []byte("test-passphrase"))
	s.haCoordinator = nil
	s.targetStore = nil
	if got := s.runScan(); got != 2*time.Minute {
		t.Fatalf("poll interval = %v, want 2m", got)
	}
	if err := s.configStore.Set(context.Background(), "renewal_policy.poll_hours", "3", "test-operator"); err != nil {
		t.Fatal(err)
	}
	if got := s.runScan(); got != 3*time.Hour {
		t.Fatalf("DB override poll interval = %v, want 3h", got)
	}
}
