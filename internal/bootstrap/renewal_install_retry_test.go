// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/agentinstall"
)

// shortLivedProvider reports one certificate as expiring in 5 days, so the
// default 30-day window makes it a candidate while its 90-day successors
// (which the retry mints) are not.
type shortLivedProvider struct {
	CertificateProvider
	fp string
}

func (p shortLivedProvider) ListCertificates(ctx context.Context, q CertificateListQuery) (CertificateListResult, error) {
	res, err := p.CertificateProvider.ListCertificates(ctx, q)
	for i := range res.Items {
		if res.Items[i].FingerprintSHA256 == p.fp {
			res.Items[i].ValidUntil = time.Now().Add(5 * 24 * time.Hour).UTC().Format(time.RFC3339)
		}
	}
	return res, err
}

type retryFixture struct {
	sched     *RenewalScheduler
	provider  CertificateProvider
	fake      *renewalFakeExecutor
	audit     *recordingAuditProvider
	notif     *recordingNotificationProvider
	predFP    string
	installed func() string // fingerprint currently on the fake host
}

func newRetryFixture(t *testing.T) *retryFixture {
	t.Helper()
	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	ctx := context.Background()
	issued, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       getFirstCAID(t, engine),
		CSRPEM:     generateTestCSRPEM(t, "sweep.example.com", "sweep.example.com"),
		TemplateID: "file-backed-default",
		TeamID:     "team-retry-" + t.Name(),
	})
	if err != nil {
		t.Fatal(err)
	}
	fp := issued.CertificateItem.FingerprintSHA256
	if _, err := provider.UpdateOwnership(ctx, fp, CertificateOwnershipRequest{OwnerEmail: "owner@example.test"}); err != nil {
		t.Fatal(err)
	}
	targets := newSweepTestTargetStore(t)
	tg := sweepTarget(true)
	tg.RenewalThresholdDays = 0
	if _, err := targets.Create(ctx, tg); err != nil {
		t.Fatal(err)
	}
	fake := &renewalFakeExecutor{files: map[string][]byte{}, failCommand: "nginx"}
	exec := newRenewalTestEngine(t, provider, fake, testSSHCredentialJSON(t))
	exec.verifier = func(context.Context, string) (string, error) {
		block, _ := pem.Decode(fake.files["/etc/nginx/tls/sweep.crt"])
		if block == nil {
			return "", contextErr("nothing installed")
		}
		return agentinstall.FingerprintSHA256(block.Bytes), nil
	}
	sched := newSweepScheduler(t, shortLivedProvider{provider, fp}, targets, exec)
	// The audit timestamp the backoff is measured from has one-second
	// resolution, so the base must exceed it for "not yet" to be observable.
	sched.pollInterval = 3 * time.Second
	f := &retryFixture{sched: sched, provider: provider, fake: fake, predFP: fp,
		audit: &recordingAuditProvider{}, notif: &recordingNotificationProvider{}}
	sched.auditProvider = f.audit
	sched.notifProvider = f.notif
	sched.cooldownStore = newFreshRenewalAlertCooldownStore(t)
	f.installed = func() string {
		block, _ := pem.Decode(fake.files["/etc/nginx/tls/sweep.crt"])
		if block == nil {
			return ""
		}
		return agentinstall.FingerprintSHA256(block.Bytes)
	}
	return f
}

func (f *retryFixture) count(action string) int { return f.audit.count(action) }

func (f *retryFixture) tickAfterBackoff(attempt int) {
	time.Sleep(installBackoff(f.sched.pollInterval, attempt) + 5*time.Millisecond)
	f.sched.runScan()
}

// A failed install is retried on a later tick without anyone intervening: the
// host is repaired between ticks, the next attempt installs and verifies, each
// attempt is audited with its number, and nothing is installed (the previous
// certificate keeps serving) until the install verifies.
func TestRenewalSweepRetriesFailedInstallUntilItVerifies(t *testing.T) {
	f := newRetryFixture(t)

	f.sched.runScan()
	if f.count("certificate.renew_execute_partial") != 1 {
		t.Fatalf("first attempt not audited: %+v", f.audit.entries)
	}

	// Still backing off: an immediate second tick must not mint another cert.
	f.sched.runScan()
	if f.count("certificate.renew_execute_partial") != 1 {
		t.Fatal("retried before the backoff elapsed")
	}
	if st := f.sched.Status(); st.PendingInstalls != 1 {
		t.Fatalf("status must show the pending install, got %+v", st)
	}

	f.fake.failCommand = "" // operator fixes the host
	f.tickAfterBackoff(1)

	if st := f.sched.Status(); st.LastAutoRenewTriggers != 1 || st.PendingInstalls != 0 {
		t.Fatalf("retry did not install: %+v", st)
	}
	var ok bool
	for _, e := range f.audit.entries {
		if e.Action == "certificate.renew_execute" && e.Outcome == "success" &&
			strings.Contains(e.ChangeSummary, "new_fingerprint="+f.installed()) && strings.Contains(e.ChangeSummary, "attempt=2") {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("retry success not audited: %+v", f.audit.entries)
	}

	// Done: later ticks leave the now-installed renewal alone.
	f.tickAfterBackoff(1)
	if f.count("certificate.renew_execute") != 1 || f.count("certificate.renew_execute_partial") != 1 {
		t.Fatalf("scheduler kept acting after a verified install: %+v", f.audit.entries)
	}
}

// A host that never recovers is attempted a bounded number of times; the final
// failure is audited as gave-up and the owner is told even inside the alert
// cooldown, then the scheduler stops.
func TestRenewalSweepGivesUpAfterBoundedAttempts(t *testing.T) {
	f := newRetryFixture(t)
	f.sched.pollInterval = 100 * time.Millisecond // backoff 100ms..800ms; only "elapsed" matters here
	for i := 1; i <= renewalInstallMaxAttempts; i++ {
		if i == 1 {
			f.sched.runScan()
		} else {
			f.tickAfterBackoff(i - 1)
		}
	}
	if got := f.count("certificate.renew_execute_partial"); got != renewalInstallMaxAttempts {
		t.Fatalf("attempts = %d, want %d", got, renewalInstallMaxAttempts)
	}
	if f.count("certificate.renew_execute_gave_up") != 1 {
		t.Fatalf("final failure not audited: %+v", f.audit.entries)
	}
	if len(f.notif.sent) != 2 {
		t.Fatalf("owner notified %d times, want 2 (first failure, and the forced final one)", len(f.notif.sent))
	}
	if st := f.sched.Status(); st.GaveUpInstalls != 1 {
		t.Fatalf("status must show the abandoned install: %+v", st)
	}

	f.tickAfterBackoff(renewalInstallMaxAttempts)
	if got := f.count("certificate.renew_execute_partial"); got != renewalInstallMaxAttempts {
		t.Fatalf("attempted again after giving up: %d", got)
	}
}
