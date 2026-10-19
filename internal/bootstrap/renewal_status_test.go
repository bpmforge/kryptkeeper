// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRenewalStatusVocabulary(t *testing.T) {
	for _, v := range renewalStatuses {
		if !validRenewalStatus(string(v)) {
			t.Errorf("%q not accepted", v)
		}
		if !strings.Contains(renewalStatusList(), string(v)) {
			t.Errorf("%q missing from the error-message list", v)
		}
	}
	for _, bad := range []string{"", "Active", "pending", "reissue-required"} {
		if validRenewalStatus(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestInstallBackoffDoublesFrom5MinToSixHourCap(t *testing.T) {
	want := []time.Duration{5 * time.Minute, 10 * time.Minute, 20 * time.Minute, 40 * time.Minute, 80 * time.Minute, 160 * time.Minute, 320 * time.Minute, 6 * time.Hour}
	for i, w := range want {
		if got := installBackoff(defaultRetryBase, defaultRetryCap, i+1); got != w {
			t.Errorf("failures=%d: got %v, want %v", i+1, got, w)
		}
	}
	if got := installBackoff(0, 0, 1); got != 5*time.Minute {
		t.Errorf("zero base/cap must use defaults, got %v", got)
	}
	if got := installBackoff(2*time.Hour, time.Hour, 3); got != 2*time.Hour {
		t.Errorf("cap below base must clamp to base, got %v", got)
	}
	if got := installBackoff(time.Minute, time.Hour, 0); got != time.Minute {
		t.Errorf("failures 0 must be treated as 1, got %v", got)
	}
	if got := installBackoff(time.Minute, time.Hour, 1000); got != time.Hour {
		t.Errorf("huge failure count must return the cap, got %v", got)
	}
}

type retryStubCerts struct {
	CertificateProvider
	items map[string]CertificateItem
}

func (p retryStubCerts) GetCertificate(_ context.Context, fp string) (CertificateDetail, bool, error) {
	it, ok := p.items[fp]
	return CertificateDetail{CertificateItem: it}, ok, nil
}

type failingRunner struct{ calls int }

func (r *failingRunner) ExecuteRenewal(context.Context, string, ManagedTarget, RenewalInstallProfile) (RenewalExecuteResult, error) {
	r.calls++
	return RenewalExecuteResult{}, errors.New("host unreachable")
}

func TestInstallBackoffReadsConfigStore(t *testing.T) {
	resetRenewalRetryStateForTest()
	t.Cleanup(resetRenewalRetryStateForTest)
	store := newFreshConfigStore(t, []byte("test-passphrase"))
	ctx := context.Background()
	if err := store.Set(ctx, "renewal_policy.retry_base_minutes", "2", "test"); err != nil {
		t.Fatal(err)
	}
	runner := &failingRunner{}
	cert := CertificateItem{FingerprintSHA256: "fp-cfg", CommonName: "cfg.example.com"}
	s := &RenewalScheduler{
		certProvider: retryStubCerts{items: map[string]CertificateItem{"fp-cfg": cert}}, auditProvider: &recordingAuditProvider{},
		configStore: store, renewalExecutor: runner, retryBase: time.Hour, // env default, overridden by the store
	}
	base, retryCap := s.resolveRetryBackoff(ctx)
	if base != 2*time.Minute || retryCap != defaultRetryCap {
		t.Fatalf("resolved base=%v cap=%v, want 2m and the default cap", base, retryCap)
	}
	T := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	st := installAttemptState{failures: 1, lastFailure: T}
	if out := s.tryAutoRenew(ctx, cert, ManagedTarget{ID: "t1"}, T.Add(119*time.Second), st, retryPolicy{base: base, retryCap: retryCap}); !out.pending || out.attempted || runner.calls != 0 {
		t.Fatalf("at T+119s the retry must still be pending: %+v calls=%d", out, runner.calls)
	}
	if out := s.tryAutoRenew(ctx, cert, ManagedTarget{ID: "t1"}, T.Add(121*time.Second), st, retryPolicy{base: base, retryCap: retryCap}); !out.attempted || runner.calls != 1 {
		t.Fatalf("at T+121s the retry must run: %+v calls=%d", out, runner.calls)
	}
	if err := store.Set(ctx, "renewal_policy.retry_cap_hours", "1", "test"); err != nil {
		t.Fatal(err)
	}
	if _, retryCap = s.resolveRetryBackoff(ctx); retryCap != time.Hour {
		t.Fatalf("cap override = %v, want 1h", retryCap)
	}
}

type retryNowFixture struct {
	mux   *http.ServeMux
	auth  *Authenticator
	audit *recordingAuditProvider
	fp    string
}

func newRetryNowFixture(t *testing.T) *retryNowFixture {
	t.Helper()
	resetRenewalRetryStateForTest()
	t.Cleanup(resetRenewalRetryStateForTest)
	t.Cleanup(func() {
		select {
		case <-renewalScanKick:
		default:
		}
	})
	auth := newReportsTestAuth(t)
	f := &retryNowFixture{auth: auth, audit: &recordingAuditProvider{}, fp: "fp-retry"}
	certs := retryStubCerts{items: map[string]CertificateItem{f.fp: {FingerprintSHA256: f.fp, CommonName: "retry.example.com"}}}
	f.mux = http.NewServeMux()
	registerRenewalExecuteHandlerWithRunner(f.mux, auth, certs, nil, nil, f.audit, nil, time.Minute)
	return f
}

func (f *retryNowFixture) post(t *testing.T, token string, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/renewal/retry", strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	return rec
}

func (f *retryNowFixture) lastOperatorOutcome() (AuditOutcome, bool) {
	f.audit.mu.Lock()
	defer f.audit.mu.Unlock()
	for i := len(f.audit.entries) - 1; i >= 0; i-- {
		if f.audit.entries[i].Action == "certificate.renew_retry" {
			return f.audit.entries[i].Outcome, true
		}
	}
	return "", false
}

func TestRetryNowRequeuesFailedRenewal(t *testing.T) {
	f := newRetryNowFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for i := 1; i <= renewalInstallMaxAttempts; i++ {
		_ = f.audit.AppendEntry(ctx, AuditEntry{Timestamp: now.Format(time.RFC3339), Action: "certificate.renew_execute_failed", ActorType: "system",
			ActorID: "renewal-scheduler", ResourceType: "certificate", ResourceID: f.fp, ChangeSummary: fmt.Sprintf("target_id=t1 attempt=%d/5 boom", i)})
	}
	recordRenewalExecuteFailure(ctx, f.fp, "t1", 5, 5, "renew_execute_failed", "boom", time.Time{}, true)
	s := &RenewalScheduler{auditProvider: f.audit}
	cert := CertificateItem{FingerprintSHA256: f.fp}
	if st, _ := s.installState(ctx, cert, "t1"); st.failures != renewalInstallMaxAttempts {
		t.Fatalf("precondition: failures = %d", st.failures)
	}

	rec := f.post(t, "reports-test-token", `{"fingerprint":"fp-retry"}`)
	if rec.Code != http.StatusAccepted || !strings.Contains(rec.Body.String(), `"queued"`) {
		t.Fatalf("retry = %d: %s", rec.Code, rec.Body.String())
	}
	if st, _ := s.installState(ctx, cert, "t1"); st.failures != 0 || !st.lastFailure.IsZero() {
		t.Fatalf("retry-now must reset the attempt budget: %+v", st)
	}
	if f.audit.count(renewalRetryRequestedAction) != 1 {
		t.Fatal("reset marker not appended")
	}
	f.audit.mu.Lock()
	for _, e := range f.audit.entries {
		if e.Action == renewalRetryRequestedAction && (e.ActorID != "renewal-scheduler" || !strings.HasPrefix(e.ChangeSummary, "requested_by=")) {
			t.Errorf("marker must be written as the scheduler and name the operator: %+v", e)
		}
	}
	f.audit.mu.Unlock()
	if out, ok := f.lastOperatorOutcome(); !ok || out != AuditOutcomeSuccess {
		t.Fatalf("operator audit row missing or wrong: %v %v", out, ok)
	}
	row, ok, _ := currentRenewalFailureStore().Get(ctx, failureKindExecute, f.fp)
	if !ok || row.NextAttemptAt.IsZero() || time.Since(row.NextAttemptAt) > 10*time.Second || row.Attempt != 5 {
		t.Fatalf("queue row must keep its fields and get next_attempt_at=now: %+v", row)
	}
	select {
	case <-renewalScanKick:
	default:
		t.Fatal("scan was not kicked")
	}
}

func TestRetryNowUnauthenticated401(t *testing.T) {
	f := newRetryNowFixture(t)
	if rec := f.post(t, "", `{"fingerprint":"fp-retry"}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d", rec.Code)
	}
	if out, ok := f.lastOperatorOutcome(); !ok || out != AuditOutcomeDenied {
		t.Fatalf("denial not audited: %v %v", out, ok)
	}
}

func TestRetryNowRequiresFingerprint400(t *testing.T) {
	f := newRetryNowFixture(t)
	if rec := f.post(t, "reports-test-token", `{}`); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "fingerprint is required") {
		t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
	}
	if out, ok := f.lastOperatorOutcome(); !ok || out != AuditOutcomeFailure {
		t.Fatalf("validation failure not audited: %v %v", out, ok)
	}
}

func TestRetryNowUnknownCertIs404(t *testing.T) {
	f := newRetryNowFixture(t)
	if rec := f.post(t, "reports-test-token", `{"fingerprint":"nope"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("got %d", rec.Code)
	}
	if out, ok := f.lastOperatorOutcome(); !ok || out != AuditOutcomeFailure {
		t.Fatalf("not-found not audited: %v %v", out, ok)
	}
}

func TestRetryNowNoQueuedFailureIs404(t *testing.T) {
	f := newRetryNowFixture(t)
	rec := f.post(t, "reports-test-token", `{"fingerprint":"fp-retry"}`)
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "no failed renewal is queued") {
		t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
	}
	if f.audit.count(renewalRetryRequestedAction) != 0 {
		t.Fatal("no marker may be written without a queued failure")
	}
	if out, ok := f.lastOperatorOutcome(); !ok || out != AuditOutcomeFailure {
		t.Fatalf("not audited: %v %v", out, ok)
	}
}

func TestRetryNowViewerIs403ThroughWriteGate(t *testing.T) {
	resetRenewalRetryStateForTest()
	t.Cleanup(resetRenewalRetryStateForTest)
	mux := http.NewServeMux()
	h := newWriteGateHarness(t, mux)
	certs := retryStubCerts{items: map[string]CertificateItem{"fp-retry": {FingerprintSHA256: "fp-retry"}}}
	registerRenewalExecuteHandlerWithRunner(mux, h.auth, certs, nil, nil, &recordingAuditProvider{}, nil, time.Minute)
	recordRenewalExecuteFailure(context.Background(), "fp-retry", "t1", 1, 5, "renew_execute_failed", "x", time.Now(), false)
	t.Cleanup(func() {
		select {
		case <-renewalScanKick:
		default:
		}
	})

	if rec := h.do(h.key(t, "viewer"), http.MethodPost, "/api/v1/renewal/retry", []byte(`{"fingerprint":"fp-retry"}`)); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer got %d: %s", rec.Code, rec.Body.String())
	}
	if rec := h.do(h.key(t, "pki-admin"), http.MethodPost, "/api/v1/renewal/retry", []byte(`{"fingerprint":"fp-retry"}`)); rec.Code != http.StatusAccepted {
		t.Fatalf("admin got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRetryNowCrossTenantIs403(t *testing.T) {
	resetRenewalRetryStateForTest()
	t.Cleanup(resetRenewalRetryStateForTest)
	mux, acmeToken, _ := setupTenantWritePathTest(t)
	recordRenewalExecuteFailure(context.Background(), "fp-globex-cert", "t1", 1, 5, "renew_execute_failed", "x", time.Now(), false)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/renewal/retry", strings.NewReader(`{"fingerprint":"fp-globex-cert"}`))
	req.Header.Set("Authorization", "Bearer "+acmeToken)
	req.Header.Set("X-Tenant", "acme")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant retry: got %d: %s", rec.Code, rec.Body.String())
	}
}
