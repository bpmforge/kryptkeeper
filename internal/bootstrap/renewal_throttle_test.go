// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"kryptkeeper/internal/connectors"
)

// peakRunner tracks how many ExecuteRenewal calls overlap.
type peakRunner struct {
	cur, peak int32
	hold      time.Duration
	err       error
	calls     int32
}

func (r *peakRunner) ExecuteRenewal(_ context.Context, fp string, target ManagedTarget, _ RenewalInstallProfile) (RenewalExecuteResult, error) {
	atomic.AddInt32(&r.calls, 1)
	n := atomic.AddInt32(&r.cur, 1)
	for {
		p := atomic.LoadInt32(&r.peak)
		if n <= p || atomic.CompareAndSwapInt32(&r.peak, p, n) {
			break
		}
	}
	time.Sleep(r.hold)
	atomic.AddInt32(&r.cur, -1)
	if r.err != nil {
		return RenewalExecuteResult{}, r.err
	}
	return RenewalExecuteResult{PredecessorFingerprint: fp, NewFingerprint: "new-" + fp + target.ID, Renewed: true, InstallOutcome: "installed_verified", Verified: true}, nil
}

func newManyCertSweep(t *testing.T, n int, runner renewalRunner) *bindingSweepFixture {
	t.Helper()
	resetRenewalRetryStateForTest()
	t.Cleanup(resetRenewalRetryStateForTest)
	var certs []CertificateItem
	var targets []ManagedTarget
	for i := 0; i < n; i++ {
		certs = append(certs, soonCert(fmt.Sprintf("fp-%d", i), fmt.Sprintf("h%d.ex.com", i)))
		targets = append(targets, armedTarget(fmt.Sprintf("t%d", i), fmt.Sprintf("h%d.ex.com", i)))
	}
	f := newBindingSweepFixture(t, certs, targets...)
	f.sched.WithRenewalRunner(runner)
	for i := 0; i < n-1; i++ {
		_, _ = f.bindings.Create(context.Background(), CertTargetBinding{CertFingerprint: certs[i].FingerprintSHA256, TargetID: targets[i].ID})
	}
	bindTo(t, f, certs[n-1].FingerprintSHA256, targets[n-1].ID)
	return f
}

func TestSweepRunsJobsConcurrentlyUpToWorkers(t *testing.T) {
	t.Setenv("KRYPTKEEPER_RENEWAL_WORKERS", "3")
	r := &peakRunner{hold: 80 * time.Millisecond}
	f := newManyCertSweep(t, 8, r)
	f.sched.runScan()
	if r.calls != 8 {
		t.Fatalf("calls = %d, want 8", r.calls)
	}
	if r.peak != 3 {
		t.Fatalf("peak concurrency = %d, want exactly the 3 workers", r.peak)
	}
	if st := f.sched.Status(); st.LastAutoRenewTriggers != 8 {
		t.Fatalf("triggers = %d", st.LastAutoRenewTriggers)
	}
}

func TestSweepSingleWorkerMatchesSerialCounters(t *testing.T) {
	t.Setenv("KRYPTKEEPER_RENEWAL_WORKERS", "1")
	r := &peakRunner{hold: 5 * time.Millisecond}
	f := newManyCertSweep(t, 4, r)
	f.sched.runScan()
	if r.peak != 1 || r.calls != 4 {
		t.Fatalf("serial run expected, peak=%d calls=%d", r.peak, r.calls)
	}
	st := f.sched.Status()
	if st.LastAutoRenewTriggers != 4 || st.PendingInstalls != 0 || st.GaveUpInstalls != 0 || st.LastCandidates != 4 {
		t.Fatalf("counters: %+v", st)
	}
}

func TestSweepMostUrgentFirst(t *testing.T) {
	t.Setenv("KRYPTKEEPER_RENEWAL_WORKERS", "1")
	var order []string
	var mu sync.Mutex
	runner := runnerFunc(func(fp string) {
		mu.Lock()
		order = append(order, fp)
		mu.Unlock()
	})
	soon := soonCert("fp-soon", "soon.ex.com")
	soon.ValidUntil = time.Now().UTC().Add(2 * 24 * time.Hour).Format(time.RFC3339)
	later := soonCert("fp-later", "later.ex.com")
	f := newBindingSweepFixture(t, []CertificateItem{later, soon}, armedTarget("t1", "later.ex.com"), armedTarget("t2", "soon.ex.com"))
	f.sched.WithRenewalRunner(runner)
	_, _ = f.bindings.Create(context.Background(), CertTargetBinding{CertFingerprint: "fp-later", TargetID: "t1"})
	bindTo(t, f, "fp-soon", "t2")
	f.sched.runScan()
	if strings.Join(order, ",") != "fp-soon,fp-later" {
		t.Fatalf("order = %v", order)
	}
}

type runnerFunc func(fp string)

func (f runnerFunc) ExecuteRenewal(_ context.Context, fp string, target ManagedTarget, _ RenewalInstallProfile) (RenewalExecuteResult, error) {
	f(fp)
	return RenewalExecuteResult{NewFingerprint: "new-" + fp, Renewed: true, InstallOutcome: "installed_verified", Verified: true}, nil
}

func TestRateLimitDefersWithoutBurningAttempts(t *testing.T) {
	rl := &connectors.RateLimitError{ConnectorID: "le", Reason: "upstream_429", RetryAfter: time.Minute}
	r := &peakRunner{err: fmt.Errorf("upstream renewal via connector le: %w", rl)}
	f := newManyCertSweep(t, 1, r)
	for i := 0; i < renewalInstallMaxAttempts+2; i++ {
		f.sched.runScan()
	}
	if got := f.audit.count(renewalDeferredAction); got != renewalInstallMaxAttempts+2 {
		t.Fatalf("deferrals audited = %d", got)
	}
	if f.audit.count("certificate.renew_execute_failed")+f.audit.count("certificate.renew_execute_partial")+f.audit.count("certificate.renew_execute_gave_up") != 0 {
		t.Fatalf("a throttled cert must not record failures: %+v", f.audit.entries)
	}
	st, err := f.sched.installState(context.Background(), CertificateItem{FingerprintSHA256: "fp-0"}, "t0")
	if err != nil || st.failures != 0 {
		t.Fatalf("attempt budget burnt: %+v %v", st, err)
	}
	if rows, _ := currentRenewalFailureStore().List(context.Background()); len(rows) != 0 {
		t.Fatalf("deferral must not enter the failure queue: %+v", rows)
	}
	f.audit.mu.Lock()
	defer f.audit.mu.Unlock()
	for _, e := range f.audit.entries {
		if e.Action == renewalDeferredAction && (e.Outcome != AuditOutcomeSkipped || !strings.Contains(e.ChangeSummary, "reason=upstream_429")) {
			t.Fatalf("deferral row wrong: %+v", e)
		}
	}
}

func TestCancelledSweepIsPendingNotFailed(t *testing.T) {
	r := &peakRunner{}
	f := newManyCertSweep(t, 2, r)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	idx := &bindingSweepIndex{}
	totals := f.sched.runRenewalJobs(ctx, []renewalJob{{cert: soonCert("a", "a"), expiry: time.Now()}, {cert: soonCert("b", "b"), expiry: time.Now()}},
		idx, time.Now(), retryPolicy{}, time.Hour)
	if totals.pending != 2 || r.calls != 0 {
		t.Fatalf("cancelled jobs must count as pending: %+v calls=%d", totals, r.calls)
	}
	out, handled := f.sched.deferredOutcome(ctx, CertificateItem{}, ManagedTarget{}, context.Canceled)
	if !handled || !out.pending {
		t.Fatalf("cancellation must defer: %+v %v", out, handled)
	}
	if _, handled := f.sched.deferredOutcome(context.Background(), CertificateItem{}, ManagedTarget{}, fmt.Errorf("boom")); handled {
		t.Fatal("a real failure must not be deferred")
	}
}

func TestJitterSeededDeterministicAndBounded(t *testing.T) {
	window := time.Hour
	a := &RenewalScheduler{jitterSeed: 42, jitterPercent: 10}
	b := &RenewalScheduler{jitterSeed: 42, jitterPercent: 10}
	c := &RenewalScheduler{jitterSeed: 43, jitterPercent: 10}
	distinctKeys := map[time.Duration]bool{}
	seedDiffers := false
	for i := 0; i < 200; i++ {
		key := fmt.Sprintf("fp-%d", i)
		ja := a.jitterFor(key, window)
		if ja != b.jitterFor(key, window) || ja != a.jitterFor(key, window) {
			t.Fatalf("same seed and key must agree for %s", key)
		}
		if ja < 0 || ja >= window/10 {
			t.Fatalf("jitter %v outside [0, %v)", ja, window/10)
		}
		distinctKeys[ja] = true
		if ja != c.jitterFor(key, window) {
			seedDiffers = true
		}
	}
	if len(distinctKeys) < 100 {
		t.Fatalf("keys barely spread: %d distinct values", len(distinctKeys))
	}
	if !seedDiffers {
		t.Fatal("a different seed must change the jitter")
	}
	if (&RenewalScheduler{jitterSeed: 42}).jitterFor("x", window) != 0 {
		t.Fatal("zero percent must disable jitter")
	}
}

func TestTickStartJitterBounded(t *testing.T) {
	s := &RenewalScheduler{jitterSeed: 7, jitterPercent: 10}
	for _, interval := range []time.Duration{time.Minute, time.Hour, 24 * time.Hour} {
		j := s.jitterFor("tick-start", interval)
		if j < 0 || j >= interval/10 {
			t.Fatalf("tick-start jitter %v for %v", j, interval)
		}
	}
	t.Setenv("RENEWAL_TICK_JITTER_PERCENT", "50")
	if tickJitterPercent() != 10 {
		t.Fatal("percent must be capped at 10")
	}
	t.Setenv("RENEWAL_TICK_JITTER_PERCENT", "0")
	if tickJitterPercent() != 0 {
		t.Fatal("0 must disable")
	}
}

func TestJitterDelaysRetryGate(t *testing.T) {
	cert := CertificateItem{FingerprintSHA256: "fp-j"}
	s := &RenewalScheduler{jitterSeed: 9, jitterPercent: 10, auditProvider: &recordingAuditProvider{}, renewalExecutor: &peakRunner{}}
	pol := retryPolicy{base: time.Minute, retryCap: time.Hour, poll: time.Hour}
	j := s.jitterFor("fp-j", time.Hour)
	if j == 0 {
		t.Skip("seed gave zero jitter")
	}
	T := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	st := installAttemptState{failures: 1, lastFailure: T}
	if out := s.tryAutoRenew(context.Background(), cert, ManagedTarget{}, T.Add(time.Minute+j-time.Second), st, pol); !out.pending || out.attempted {
		t.Fatalf("must still wait out the jitter: %+v", out)
	}
}

func TestObserverEmitsRateLimitedAudit(t *testing.T) {
	audit := &recordingAuditProvider{}
	s := &RenewalScheduler{auditProvider: audit}
	s.installThrottleObserver()
	t.Cleanup(func() { connectors.DefaultThrottle.SetObserver(nil) })

	release, err := connectors.DefaultThrottle.Acquire(context.Background(), "obs-test")
	if err != nil {
		t.Fatal(err)
	}
	release(&connectors.RateLimitError{ConnectorID: "obs-test", Reason: "upstream_429", RetryAfter: 2 * time.Minute})

	audit.mu.Lock()
	defer audit.mu.Unlock()
	if len(audit.entries) != 1 {
		t.Fatalf("entries = %+v", audit.entries)
	}
	e := audit.entries[0]
	if e.Action != "connector.rate_limited" || e.Outcome != AuditOutcomeDenied || e.ResourceID != "obs-test" || e.ResourceType != "connector" ||
		e.ActorID != "connector-throttle" || !strings.Contains(e.ChangeSummary, "reason=upstream_429") || !strings.Contains(e.ChangeSummary, "retry_after=2m0s") {
		t.Fatalf("audit row wrong: %+v", e)
	}
}

func TestSLOReportExposesQueue(t *testing.T) {
	resetRenewalRetryStateForTest()
	t.Cleanup(resetRenewalRetryStateForTest)
	empty, err := json.Marshal(renewalQueueReport(connectors.NewThrottle(connectors.Limits{}, time.Now)))
	if err != nil || !strings.Contains(string(empty), `"connectors":[]`) || !strings.Contains(string(empty), `"connector_budgets":[]`) {
		t.Fatalf("empty queue must serialise empty arrays: %s %v", empty, err)
	}

	release, err := connectors.DefaultThrottle.Acquire(context.Background(), "slo-q")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { release(nil) })
	renewalQueueState.mu.Lock()
	renewalQueueState.depth, renewalQueueState.workers, renewalQueueState.avgJobSecs, renewalQueueState.finished = 4, 2, 3, 1
	renewalQueueState.mu.Unlock()
	t.Cleanup(func() { queueSetDepth(0, 0) })

	auth := newReportsTestAuth(t)
	mux := http.NewServeMux()
	registerRenewalSLOHandler(mux, auth, NewAgentStore(), &reportCertProvider{}, stubAuditProvider{})
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
	q := resp.Data.Queue
	if q.Depth != 4 || q.Workers != 2 || !q.ETAKnown || q.ETASeconds != 6 {
		t.Fatalf("queue = %+v, want depth 4, 2 workers, eta 6s", q)
	}
	var found bool
	for _, b := range q.ConnectorBudgets {
		if b.ConnectorID == "slo-q" && b.InFlight == 1 && b.Cap == 10 {
			found = true
		}
	}
	if !found || q.Connectors == nil {
		t.Fatalf("connector budgets missing slo-q: %+v", q)
	}
}
