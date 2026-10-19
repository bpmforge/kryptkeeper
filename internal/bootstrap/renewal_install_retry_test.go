// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
	sched.retryBase = 3 * time.Second
	sched.retryCap = time.Hour
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
	time.Sleep(installBackoff(f.sched.retryBase, f.sched.retryCap, attempt) + 5*time.Millisecond)
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
	f.sched.retryBase = 100 * time.Millisecond // backoff 100ms..800ms; only "elapsed" matters here
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

// failedRenewalRows fetches GET /reports/renewal-slo through a freshly built
// handler, so a test can swap the queue store between calls like a restart.
func failedRenewalRows(t *testing.T) []FailedRenewal {
	t.Helper()
	auth := newReportsTestAuth(t)
	mux := http.NewServeMux()
	registerRenewalSLOHandler(mux, auth, NewAgentStore(), &reportCertProvider{}, stubAuditProvider{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/renewal-slo", nil)
	req.Header.Set("Authorization", "Bearer reports-test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("renewal-slo = %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data RenewalSLOReport `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp.Data.FailedRenewals
}

func newFileRenewalFailureStore(t *testing.T, path string) *sqlRenewalFailureStore {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s := &sqlRenewalFailureStore{db: db}
	if err := s.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s
}

func useRenewalFailureStore(t *testing.T, s renewalFailureStore) {
	t.Helper()
	SetRenewalFailureStore(s)
	t.Cleanup(resetRenewalRetryStateForTest)
}

func findFailure(rows []FailedRenewal, fp string) (FailedRenewal, bool) {
	for _, r := range rows {
		if r.Fingerprint == fp {
			return r, true
		}
	}
	return FailedRenewal{}, false
}

func TestFailedRenewalQueueSurvivesHubRestart(t *testing.T) {
	f := newRetryFixture(t)
	path := filepath.Join(t.TempDir(), "queue.db")
	useRenewalFailureStore(t, newFileRenewalFailureStore(t, path))

	f.sched.runScan()
	row, ok := findFailure(failedRenewalRows(t), f.predFP)
	if !ok || row.Type != "execute_failure" || row.Attempt != 1 || row.NextAttemptAt == "" || row.GaveUp {
		t.Fatalf("expected a pending execute_failure row, got %+v (found=%v)", row, ok)
	}

	// Restart: a second store on the same file, a brand-new handler.
	useRenewalFailureStore(t, newFileRenewalFailureStore(t, path))
	row, ok = findFailure(failedRenewalRows(t), f.predFP)
	if !ok || row.Type != "execute_failure" || row.Attempt != 1 {
		t.Fatalf("failure lost across restart: %+v (found=%v)", row, ok)
	}
}

func TestFailedRenewalQueueClearedOnSuccess(t *testing.T) {
	f := newRetryFixture(t)
	useRenewalFailureStore(t, newMemRenewalFailureStore())

	f.sched.runScan()
	if _, ok := findFailure(failedRenewalRows(t), f.predFP); !ok {
		t.Fatal("failure not queued")
	}
	f.fake.failCommand = ""
	f.tickAfterBackoff(1)
	if _, ok := findFailure(failedRenewalRows(t), f.predFP); ok {
		t.Fatal("success must clear the queue entry")
	}
}

func TestFailedRenewalQueueGivesUpAtAttempt5WithTwoNotifications(t *testing.T) {
	f := newRetryFixture(t)
	useRenewalFailureStore(t, newMemRenewalFailureStore())
	f.sched.retryBase = 100 * time.Millisecond
	for i := 1; i <= renewalInstallMaxAttempts; i++ {
		if i == 1 {
			f.sched.runScan()
		} else {
			f.tickAfterBackoff(i - 1)
		}
	}
	row, ok := findFailure(failedRenewalRows(t), f.predFP)
	if !ok || row.Attempt != renewalInstallMaxAttempts || !row.GaveUp || row.NextAttemptAt != "" {
		t.Fatalf("expected gave-up attempt-5 row without next attempt, got %+v (found=%v)", row, ok)
	}
	if len(f.notif.sent) != 2 {
		t.Fatalf("notifications = %d, want 2", len(f.notif.sent))
	}
}

func TestFailedRenewalListUnifiesExecuteAndNotificationFailures(t *testing.T) {
	useRenewalFailureStore(t, newMemRenewalFailureStore())
	recordRenewalExecuteFailure(context.Background(), "fp-exec", "t1", 2, 5, "renew_execute_failed", "boom", time.Now().Add(time.Minute), false)
	for i := 0; i < renewalTriggerMaxAttempts; i++ {
		recordRenewalTriggerFailure("fp-notif", "smtp down")
	}
	recordRenewalTriggerFailure("fp-notif-young", "smtp down") // under budget: not listed

	auth := newReportsTestAuth(t)
	store := NewAgentStore()
	seedAgentWithResults(t, store, "a1", []AgentRenewalResult{
		{TaskID: "t1", Fingerprint: "fp-agent", Outcome: "reload_failed", RolledBack: true, ReportedAt: "2026-06-16T12:00:00Z"},
	})
	mux := http.NewServeMux()
	registerRenewalSLOHandler(mux, auth, store, &reportCertProvider{}, stubAuditProvider{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/renewal-slo", nil)
	req.Header.Set("Authorization", "Bearer reports-test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var resp struct {
		Data RenewalSLOReport `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	types := map[string]string{}
	for _, r := range resp.Data.FailedRenewals {
		types[r.Fingerprint] = r.Type
	}
	want := map[string]string{"fp-exec": "execute_failure", "fp-notif": "notification_dead_letter", "fp-agent": "agent_result"}
	if len(types) != 3 {
		t.Fatalf("rows = %v, want %v", types, want)
	}
	for fp, ty := range want {
		if types[fp] != ty {
			t.Errorf("%s type = %q, want %q", fp, types[fp], ty)
		}
	}
}

func TestRenewalFailureStoreContract(t *testing.T) {
	stores := map[string]func(t *testing.T) renewalFailureStore{
		"mem": func(*testing.T) renewalFailureStore { return newMemRenewalFailureStore() },
		"sqlite": func(t *testing.T) renewalFailureStore {
			return newFileRenewalFailureStore(t, filepath.Join(t.TempDir(), "c.db"))
		},
	}
	for name, mk := range stores {
		t.Run(name, func(t *testing.T) {
			s := mk(t)
			ctx := context.Background()
			t0 := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
			if err := s.Upsert(ctx, renewalFailureRecord{Kind: failureKindExecute, Fingerprint: "a", Attempt: 1, LastFailedAt: t0, NextAttemptAt: t0.Add(time.Minute)}); err != nil {
				t.Fatal(err)
			}
			if err := s.Upsert(ctx, renewalFailureRecord{Kind: failureKindExecute, Fingerprint: "a", Attempt: 2, GaveUp: true, LastFailedAt: t0.Add(time.Hour), FirstFailedAt: t0.Add(time.Hour)}); err != nil {
				t.Fatal(err)
			}
			got, ok, err := s.Get(ctx, failureKindExecute, "a")
			if err != nil || !ok {
				t.Fatalf("get: %v %v", ok, err)
			}
			if !got.FirstFailedAt.Equal(t0) || got.Attempt != 2 || !got.GaveUp || !got.NextAttemptAt.IsZero() {
				t.Fatalf("upsert must keep first_failed_at and replace the rest: %+v", got)
			}
			_ = s.Upsert(ctx, renewalFailureRecord{Kind: failureKindNotification, Fingerprint: "b", LastFailedAt: t0.Add(2 * time.Hour)})
			_ = s.Upsert(ctx, renewalFailureRecord{Kind: failureKindNotification, Fingerprint: "a", LastFailedAt: t0.Add(2 * time.Hour)})
			list, err := s.List(ctx)
			if err != nil || len(list) != 3 {
				t.Fatalf("list: %v %+v", err, list)
			}
			if list[0].Fingerprint != "a" || list[0].Kind != failureKindNotification || list[1].Fingerprint != "b" || list[2].Kind != failureKindExecute {
				t.Fatalf("order must be newest first then fingerprint: %+v", list)
			}
			for i := 0; i < 2; i++ {
				if err := s.Delete(ctx, failureKindExecute, "a"); err != nil {
					t.Fatalf("delete #%d: %v", i, err)
				}
			}
			if _, ok, _ := s.Get(ctx, failureKindExecute, "a"); ok {
				t.Fatal("row still present after delete")
			}
		})
	}
}
