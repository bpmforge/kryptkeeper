// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/acme"

	"kryptkeeper/internal/connectors"
)

// W26-28: Retry-After backoff gate. Fake clock via acmeNow, fixed jitter, no sleeps.

type rlHarness struct {
	now    time.Time
	mu     sync.Mutex
	alerts []string
}

func (h *rlHarness) clock() time.Time { h.mu.Lock(); defer h.mu.Unlock(); return h.now }
func (h *rlHarness) advance(d time.Duration) {
	h.mu.Lock()
	h.now = h.now.Add(d)
	h.mu.Unlock()
}

func newRLHarness(t *testing.T, jitter time.Duration) *rlHarness {
	t.Helper()
	h := &rlHarness{now: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	oldNow, oldJit, oldAlert, oldBO, oldStuck, oldOnce := acmeNow, acmeJitter, acmeAlert, acmeBackoff, acmeStuckOrders, acmeIssueOnce
	acmeNow = h.clock
	acmeJitter = func() time.Duration { return jitter }
	acmeAlert = func(event, _, _ string) { h.mu.Lock(); h.alerts = append(h.alerts, event); h.mu.Unlock() }
	acmeBackoff = newMemoryBackoff()
	acmeStuckOrders = &stuckCounter{n: map[string]int{}}
	t.Cleanup(func() {
		acmeNow, acmeJitter, acmeAlert, acmeBackoff, acmeStuckOrders, acmeIssueOnce = oldNow, oldJit, oldAlert, oldBO, oldStuck, oldOnce
	})
	return h
}

func (h *rlHarness) alertCount(event string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, a := range h.alerts {
		if a == event {
			n++
		}
	}
	return n
}

// rateLimitingCA wraps the in-repo CA: new-order answers 429 + Retry-After
// while limited is set. Returns the upstream URL, solver port and order counter.
func rateLimitingCA(t *testing.T, limited *atomic.Bool, retryAfter, body string) (upstream string, port int, orders *atomic.Int32) {
	t.Helper()
	port = freeLocalPort(t)
	orders = &atomic.Int32{}
	upstream = newARIUpstream(t, fmt.Sprintf("127.0.0.1:%d", port), func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && r.URL.Path == "/acme/new-order" {
				orders.Add(1)
				if limited.Load() {
					if body == "" {
						w.Header().Set("Content-Type", "application/problem+json")
						body = `{"type":"urn:ietf:params:acme:error:rateLimited","detail":"too many"}`
					}
					if retryAfter != "" {
						w.Header().Set("Retry-After", retryAfter)
					}
					w.WriteHeader(http.StatusTooManyRequests)
					_, _ = w.Write([]byte(body))
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	})
	return upstream, port, orders
}

func issueRL(t *testing.T, conn *acmeIssuerConnector) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err := conn.Issue(ctx, connectors.IssueRequest{CSRPEM: generateTestCSRPEM(t, acmeTestHost)})
	return err
}

func rlConnector(t *testing.T, retryAfter, body string) (*acmeIssuerConnector, *atomic.Bool, *atomic.Int32) {
	t.Helper()
	var limited atomic.Bool
	limited.Store(true)
	upstream, port, orders := rateLimitingCA(t, &limited, retryAfter, body)
	return newACMETestConnector(t, upstream, port, nil).(*acmeIssuerConnector), &limited, orders
}

func rlRetryAt(t *testing.T, err error) *acmeRateLimitError {
	t.Helper()
	if !errors.Is(err, errACMERateLimited) {
		t.Fatalf("want errACMERateLimited, got %v", err)
	}
	var rl *acmeRateLimitError
	if !errors.As(err, &rl) {
		t.Fatalf("not an acmeRateLimitError: %v", err)
	}
	return rl
}

func TestRateLimitedOrderBlocksForRetryAfterPlusJitter(t *testing.T) {
	h := newRLHarness(t, 30*time.Second)
	t0 := h.clock()
	conn, _, orders := rlConnector(t, "600", "")
	rl := rlRetryAt(t, issueRL(t, conn))
	if want := t0.Add(630 * time.Second); !rl.RetryAt.Equal(want) {
		t.Fatalf("RetryAt = %s, want %s", rl.RetryAt, want)
	}
	if d := rl.RetryAt.Sub(t0); d < 600*time.Second || d-600*time.Second > 60*time.Second {
		t.Fatalf("delay %s outside [600s, 660s]", d)
	}
	if orders.Load() != 1 {
		t.Fatalf("CA saw %d new-orders, want exactly 1 (client must not sleep-retry a 429)", orders.Load())
	}
	if !strings.Contains(rl.Reason, "too many") {
		t.Fatalf("reason should carry CA detail, got %q", rl.Reason)
	}
}

func TestGateClosedMakesNoCARequest(t *testing.T) {
	h := newRLHarness(t, 30*time.Second)
	conn, limited, orders := rlConnector(t, "600", "")
	rlRetryAt(t, issueRL(t, conn))
	h.advance(599 * time.Second)
	rlRetryAt(t, issueRL(t, conn))
	if orders.Load() != 1 {
		t.Fatalf("closed gate must not hit the CA; orders=%d", orders.Load())
	}
	limited.Store(false)
	h.advance(32 * time.Second) // t0+631s
	if err := issueRL(t, conn); err != nil {
		t.Fatalf("issue after gate opened: %v", err)
	}
	if orders.Load() != 2 {
		t.Fatalf("orders=%d, want 2", orders.Load())
	}
	if _, blocked := acmeBackoff.BlockedUntil(conn.id, h.clock()); blocked {
		t.Fatal("success must clear the gate")
	}
}

func TestRateLimitWithoutRetryAfterUsesDefault(t *testing.T) {
	h := newRLHarness(t, 0)
	conn, _, _ := rlConnector(t, "", "")
	rl := rlRetryAt(t, issueRL(t, conn))
	if got := rl.RetryAt.Sub(h.clock()); got != defaultRateLimitWait {
		t.Fatalf("wait = %s, want %s", got, defaultRateLimitWait)
	}
}

func TestHugeRetryAfterIsClamped(t *testing.T) {
	h := newRLHarness(t, 0)
	conn, _, _ := rlConnector(t, "99999999", "")
	rl := rlRetryAt(t, issueRL(t, conn))
	if got := rl.RetryAt.Sub(h.clock()); got != maxRateLimitWait {
		t.Fatalf("wait = %s, want %s", got, maxRateLimitWait)
	}
}

func TestStatus429WithPlainBodyIsRateLimit(t *testing.T) {
	h := newRLHarness(t, 0)
	conn, _, _ := rlConnector(t, "120", "slow down")
	rl := rlRetryAt(t, issueRL(t, conn))
	if got := rl.RetryAt.Sub(h.clock()); got != 120*time.Second {
		t.Fatalf("wait = %s, want 120s", got)
	}
}

func TestWrappedErrorIsUnwrapped(t *testing.T) {
	ae := &acme.Error{StatusCode: 429, ProblemType: "urn:ietf:params:acme:error:rateLimited", Header: http.Header{"Retry-After": {"600"}}}
	wrapped := fmt.Errorf("outer: %w", fmt.Errorf("acme order: %w", ae))
	if _, direct := acme.RateLimit(wrapped); direct {
		t.Fatal("precondition: acme.RateLimit must not see through wrapping")
	}
	if wait, ok := ACMERetryAfter(wrapped); !ok || wait != 600*time.Second {
		t.Fatalf("ACMERetryAfter = %s,%v", wait, ok)
	}
	if _, ok := ACMERetryAfter(errors.New("boom")); ok {
		t.Fatal("non-acme error is not a rate limit")
	}
}

func TestStuckPendingOrderIsRetriedThenFails(t *testing.T) {
	h := newRLHarness(t, 0)
	conn := newACMETestConnector(t, "http://127.0.0.1:1", 0, nil).(*acmeIssuerConnector)
	stuckErr := fmt.Errorf("acme order: %w", &acme.OrderError{Status: "pending"})
	mode := "stuck"
	acmeIssueOnce = func(*acmeIssuerConnector, context.Context, connectors.IssueRequest) (connectors.IssueResult, error) {
		if mode == "ok" {
			return connectors.IssueResult{FingerprintSHA256: "fp"}, nil
		}
		return connectors.IssueResult{}, stuckErr
	}
	attempt := func() error { return issueRL(t, conn) }
	for i := 1; i <= 2; i++ {
		rl := rlRetryAt(t, attempt())
		if rl.Reason != "order stuck pending, retrying" {
			t.Fatalf("attempt %d reason %q", i, rl.Reason)
		}
		h.advance(stuckOrderWait + time.Second)
	}
	// A success resets the counter.
	mode = "ok"
	if err := attempt(); err != nil {
		t.Fatalf("success: %v", err)
	}
	mode = "stuck"
	for i := 1; i <= stuckOrderMaxRetries-1; i++ {
		rlRetryAt(t, attempt())
		h.advance(stuckOrderWait + time.Second)
	}
	if h.alertCount("acme.upstream.order.failed") != 0 {
		t.Fatal("alert fired before retries exhausted")
	}
	err := attempt()
	if errors.Is(err, errACMERateLimited) || !errors.Is(err, stuckErr) {
		t.Fatalf("attempt %d must surface the original error, got %v", stuckOrderMaxRetries, err)
	}
	if h.alertCount("acme.upstream.order.failed") != 1 {
		t.Fatal("want one order.failed alert")
	}
}

// rateLimitingConnector blocks the gate like the real one and returns a wrapped typed error.
type rateLimitingConnector struct {
	recordingConnector
	calls atomic.Int32
}

func (c *rateLimitingConnector) Issue(context.Context, connectors.IssueRequest) (connectors.IssueResult, error) {
	c.calls.Add(1)
	until := acmeNow().Add(630 * time.Second)
	acmeBackoff.Block(c.id, until)
	return connectors.IssueResult{}, fmt.Errorf("x: %w", &acmeRateLimitError{ConnectorID: c.id, RetryAt: until, Reason: "too many"})
}

func TestSchedulerDefersRateLimitedRenewal(t *testing.T) {
	h := newRLHarness(t, 0)
	t.Setenv("RENEWAL_POLL_MINUTES", "1")
	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	ctx := context.Background()
	issued, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID: getFirstCAID(t, engine), CSRPEM: generateTestCSRPEM(t, "sweep.example.com", "sweep.example.com"),
		TemplateID: "file-backed-default", TeamID: "team-sweep",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.UpdateEstate(ctx, issued.CertificateItem.FingerprintSHA256, EstateUpdate{
		ManagementState: "managed", RenewalMethod: "acme", RenewalConnectorID: "conn-fake-up",
	}); err != nil {
		t.Fatal(err)
	}
	targets := newSweepTestTargetStore(t)
	tgt := sweepTarget(true)
	tgt.RenewalThresholdDays = 1
	if _, err := targets.Create(ctx, tgt); err != nil {
		t.Fatal(err)
	}
	fake := &renewalFakeExecutor{files: map[string][]byte{}}
	exec := newRenewalTestEngine(t, provider, fake, testSSHCredentialJSON(t))
	rc := &rateLimitingConnector{recordingConnector: recordingConnector{id: "conn-fake-up", pem: estateTestCertPEM(t)}}
	reg := connectors.NewRegistry()
	reg.Register(rc)
	exec.WithConnectorRegistry(reg)

	sched := newSweepScheduler(t, provider, targets, exec)
	audit := &auditRecorder{}
	sched.auditProvider = audit
	sched.WithARIDue(func(context.Context, CertificateItem, time.Time) ARIDecision {
		return ARIDecision{Known: true, Due: true, Detail: "ari_window=past"}
	})

	sched.runScan()
	if audit.count("acme.upstream.ratelimited") != 1 {
		t.Fatalf("want 1 ratelimited audit, got %v", audit.actions)
	}
	for _, bad := range []string{"certificate.renew_execute_failed", "certificate.renew_execute_gave_up", "certificate.renew_execute_partial"} {
		if audit.count(bad) != 0 {
			t.Fatalf("rate limit must not be a failure: %s in %v", bad, audit.actions)
		}
	}
	if h.alertCount("acme.upstream.ratelimited") != 1 {
		t.Fatalf("alert hook calls = %d, want 1", h.alertCount("acme.upstream.ratelimited"))
	}

	// Next ticks while backed off: no CA call, no new audit rows (renew/ratelimited deduped).
	sched.runScan()
	sched.runScan()
	if rc.calls.Load() != 1 {
		t.Fatalf("connector called %d times while backed off, want 1", rc.calls.Load())
	}
	if audit.count("acme.upstream.renew") != 1 || audit.count("acme.upstream.ratelimited") != 1 {
		t.Fatalf("audit rows must be deduped while backed off: %v", audit.actions)
	}

	// Gate opens: the cert is retried, not lost.
	h.advance(631 * time.Second)
	sched.runScan()
	if rc.calls.Load() != 2 {
		t.Fatalf("after gate opens want a retry, calls=%d", rc.calls.Load())
	}
}

// W27-34 regression: an order already in flight when a sibling drew a 429
// finishes successfully; its success must not reopen the connector gate (the
// storm run sent ~4x the CA limit hits once successes erased the gate).
func TestInFlightSuccessDoesNotReopenGateClosedBySibling429(t *testing.T) {
	h := newRLHarness(t, 0)
	conn := &acmeIssuerConnector{id: "conn-x"}
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	acmeIssueOnce = func(_ *acmeIssuerConnector, _ context.Context, _ connectors.IssueRequest) (connectors.IssueResult, error) {
		if calls.Add(1) == 1 { // the slow, successful sibling
			close(started)
			<-release
			return connectors.IssueResult{}, nil
		}
		return connectors.IssueResult{}, &acme.Error{StatusCode: http.StatusTooManyRequests, Header: http.Header{"Retry-After": {"600"}}}
	}
	done := make(chan error, 1)
	go func() { _, err := conn.Issue(context.Background(), connectors.IssueRequest{}); done <- err }()
	<-started
	if err := func() error { _, e := conn.Issue(context.Background(), connectors.IssueRequest{}); return e }(); !errors.Is(err, errACMERateLimited) {
		t.Fatalf("second issue should be rate limited, got %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, backedOff := acmeConnectorBackedOff("conn-x"); !backedOff {
		t.Fatal("a sibling's late success reopened the gate the 429 closed")
	}
	h.advance(601 * time.Second)
	if _, backedOff := acmeConnectorBackedOff("conn-x"); backedOff {
		t.Fatal("gate should lapse after Retry-After")
	}
}

// A renewal deferred by the connector gate must be retried when the gate
// lapses, not a whole poll interval later (storm run: one 429 cost a 60 s tick).
func TestGateDeferredRenewalsRescanWhenGateLapses(t *testing.T) {
	s := &RenewalScheduler{scanNow: make(chan struct{}, 1)}
	s.noteGateWake(time.Now().Add(50 * time.Millisecond))
	s.armGateWake(time.Hour)
	select {
	case <-s.scanNow:
	case <-time.After(3 * time.Second):
		t.Fatal("no rescan when the gate lapsed")
	}
	s.noteGateWake(time.Now().Add(2 * time.Hour)) // beyond the next poll: the poll covers it
	s.armGateWake(time.Hour)
	select {
	case <-s.scanNow:
		t.Fatal("rescan armed for a gate that outlives the poll interval")
	case <-time.After(400 * time.Millisecond):
	}
}
