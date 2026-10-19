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

	"kryptkeeper/internal/connectors"
)

// rateLimitedOrders makes the first newOrder answer 429 with Retry-After and
// counts every newOrder that arrives while that window is still running.
type rateLimitedOrders struct {
	mu         sync.Mutex
	retryAfter time.Duration
	blockedAt  time.Time
	untilAt    time.Time
	orders     int
	violations int
	limited    chan struct{}
}

func newRateLimitedOrders(retryAfter time.Duration) *rateLimitedOrders {
	return &rateLimitedOrders{retryAfter: retryAfter, limited: make(chan struct{})}
}

func (r *rateLimitedOrders) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost || req.URL.Path != "/acme/new-order" {
			next.ServeHTTP(w, req)
			return
		}
		r.mu.Lock()
		now := time.Now()
		switch {
		case r.blockedAt.IsZero():
			r.blockedAt, r.untilAt = now, now.Add(r.retryAfter)
			close(r.limited)
			r.mu.Unlock()
			w.Header().Set("Retry-After", fmt.Sprint(int(r.retryAfter.Seconds())))
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"type":"urn:ietf:params:acme:error:rateLimited","detail":"slow down"}`))
			return
		case now.Before(r.untilAt):
			r.violations++
		}
		r.orders++
		r.mu.Unlock()
		next.ServeHTTP(w, req)
	})
}

// A 429 the ACME client retries internally never reaches the throttle's
// post-release backoff, so a sibling issuance used to send its newOrder into
// the CA's Retry-After window (the "late" violations W27-34 measured). The
// connector now reports the Retry-After to the throttle's upstream gate and
// the sibling parks behind it.
func TestACMESiblingIssuanceHonoursRetryAfterOfAnotherOrder(t *testing.T) {
	isolateACMERateLimitGate(t)
	solverPort := freeLocalPort(t)
	ca := newRateLimitedOrders(time.Second)
	upstream := newTestUpstreamACMEWrapped(t, fmt.Sprintf("127.0.0.1:%d", solverPort), ca.wrap)
	db := setupIntegrationDB(t)
	inventory, _ := newIntegrationCAProvider(t, db)

	th := connectors.NewThrottle(connectors.Limits{MaxConcurrent: 10}, time.Now)
	first := connectors.NewRegistry().WithThrottle(th)
	first.Register(newACMETestConnector(t, upstream, solverPort, inventory))
	// The sibling only needs to get its newOrder out; it fails at the
	// challenge afterwards because nothing serves its solver port.
	sibling := connectors.NewRegistry().WithThrottle(th)
	sibling.Register(newACMETestConnector(t, upstream, freeLocalPort(t), nil))

	var wg sync.WaitGroup
	var firstErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, firstErr = first.Issue(context.Background(), "conn-acme-test", connectors.IssueRequest{CSRPEM: generateTestCSRPEM(t, acmeTestHost), TeamID: "team-acme"})
	}()
	select {
	case <-ca.limited:
	case <-time.After(20 * time.Second):
		t.Fatal("the first order never reached the CA")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, siblingErr := sibling.Issue(ctx, "conn-acme-test", connectors.IssueRequest{CSRPEM: generateTestCSRPEM(t, acmeTestHost)})
	wg.Wait()
	// Since the v0.14 merge the 429 surfaces to the caller (W26-28 gate)
	// instead of being slept through; the scheduler defers and retries it.
	if _, limited := rateLimitWait(firstErr); !limited {
		t.Fatalf("the rate-limited order must surface as a rate limit, got %v", firstErr)
	}
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if ca.violations != 0 {
		t.Fatalf("%d newOrder request(s) reached the CA inside its Retry-After window", ca.violations)
	}
	// The sibling either waited out the hold and ordered after the window,
	// or the W26-28 gate refused it up front as rate limited; both keep the
	// CA's window. If it waited and ordered, it then fails at the challenge
	// (nothing serves its solver port); that is the expected tail, anything
	// else is a regression. The window check is ca.violations above.
	if siblingErr != nil && !strings.Contains(siblingErr.Error(), "acme challenge validation") {
		if _, limited := rateLimitWait(siblingErr); !limited {
			t.Fatalf("the sibling failed for another reason: %v", siblingErr)
		}
	}
}

// Once the process is draining a 429 is not slept through: it surfaces as a
// rate limit and the W26-28 connector gate owns the wait, so a graceful stop is not held for the CA's window.
func TestACMEDrainSurfacesRateLimitInsteadOfRetrying(t *testing.T) {
	isolateACMERateLimitGate(t)
	solverPort := freeLocalPort(t)
	ca := newRateLimitedOrders(30 * time.Second)
	upstream := newTestUpstreamACMEWrapped(t, fmt.Sprintf("127.0.0.1:%d", solverPort), ca.wrap)
	th := connectors.NewThrottle(connectors.Limits{MaxConcurrent: 10}, time.Now)
	reg := connectors.NewRegistry().WithThrottle(th)
	reg.Register(newACMETestConnector(t, upstream, solverPort, nil))

	drain := make(chan struct{})
	close(drain)
	ctx, cancel := context.WithTimeout(connectors.WithDrain(context.Background(), drain), 20*time.Second)
	defer cancel()
	start := time.Now()
	_, err := reg.Issue(ctx, "conn-acme-test", connectors.IssueRequest{CSRPEM: generateTestCSRPEM(t, acmeTestHost)})
	if _, limited := rateLimitWait(err); !limited {
		t.Fatalf("a draining 429 must surface as a rate limit, got %v", err)
	}
	if time.Since(start) > 10*time.Second {
		t.Fatalf("drain slept through the CA's Retry-After (%s)", time.Since(start))
	}
	if _, blocked := acmeConnectorBackedOff("conn-acme-test"); !blocked {
		t.Fatal("the ACME connector gate must hold the connector after the 429")
	}
}

// W27-34 run B: a graceful stop used to return while renewals were mid-flight,
// so the process exited between "CA minted the certificate" and "installed" and
// the next start issued again. Stop now lets running jobs finish and starts no
// new ones.
func TestStopDrainsInFlightRenewalsAndStartsNoNewOnes(t *testing.T) {
	t.Setenv("KRYPTKEEPER_RENEWAL_WORKERS", "2")
	r := &peakRunner{hold: 300 * time.Millisecond}
	f := newManyCertSweep(t, 6, r)
	f.sched.stop = make(chan struct{})
	scanDone := make(chan struct{})
	go func() { f.sched.runScan(); close(scanDone) }()
	for atomic.LoadInt32(&r.calls) < 2 {
		time.Sleep(5 * time.Millisecond)
	}
	f.sched.Stop()
	if cur := atomic.LoadInt32(&r.cur); cur != 0 {
		t.Fatalf("Stop returned with %d renewal(s) still in flight", cur)
	}
	<-scanDone
	if calls := atomic.LoadInt32(&r.calls); calls != 2 {
		t.Fatalf("calls = %d, want only the 2 already running; a stopped scheduler must start no new renewal", calls)
	}
	if st := f.sched.Status(); st.PendingInstalls != 4 || st.LastAutoRenewTriggers != 2 {
		t.Fatalf("skipped jobs must count as pending, not failed: %+v", st)
	}
}

func TestStopDrainGivesUpAfterTimeout(t *testing.T) {
	t.Setenv("KRYPTKEEPER_SHUTDOWN_DRAIN", "100ms")
	t.Setenv("KRYPTKEEPER_RENEWAL_WORKERS", "1")
	r := &peakRunner{hold: 2 * time.Second}
	f := newManyCertSweep(t, 1, r)
	f.sched.stop = make(chan struct{})
	go f.sched.runScan()
	for atomic.LoadInt32(&r.calls) < 1 {
		time.Sleep(5 * time.Millisecond)
	}
	start := time.Now()
	f.sched.Stop()
	if d := time.Since(start); d > time.Second {
		t.Fatalf("Stop blocked %s past its drain budget", d)
	}
}

// isolateACMERateLimitGate gives a test a fresh W26-28 connector gate; the
// package-level one keys by connector ID and other ACME tests share the id.
func isolateACMERateLimitGate(t *testing.T) {
	t.Helper()
	prev := acmeBackoff
	acmeBackoff = newMemoryBackoff()
	t.Cleanup(func() { acmeBackoff = prev })
}

// renewal/execute maps the ACME connector's own gate refusal to 429 too, not
// only the W27-33 throttle's and raw ACME 429s.
func TestRateLimitWaitRecognisesACMEGateRefusal(t *testing.T) {
	err := fmt.Errorf("renew: %w", &acmeRateLimitError{ConnectorID: "c", RetryAt: time.Now().Add(90 * time.Second), Reason: "gate still closed"})
	d, ok := rateLimitWait(err)
	if !ok || d < 80*time.Second || d > 90*time.Second {
		t.Fatalf("rateLimitWait = %s, %v; want ~90s, true", d, ok)
	}
	if _, ok := rateLimitWait(errors.New("boom")); ok {
		t.Fatal("a plain error is not a rate limit")
	}
}
