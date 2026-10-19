// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"kryptkeeper/internal/logging"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/connectors"
)

// W27-33: the renewal sweep's admission control. The per-connector cap, 429
// backoff and daily budget live in connectors.Throttle (one gate for every
// upstream issuance); this file adds the sweep's worker pool, seeded jitter,
// queue metrics and the audit hooks. Kept out of renewal_scheduler.go, which
// other lanes also edit.

const (
	defaultRenewalWorkers = 16
	maxTickJitterPercent  = 10

	renewalDeferredAction = "certificate.renew_execute_deferred"
	connectorRateLimited  = "connector.rate_limited"
)

// retryPolicy is one tick's resolved retry shape: backoff base and cap, and
// the poll interval the per-certificate jitter is a fraction of.
type retryPolicy struct {
	base, retryCap, poll time.Duration
}

// renewalWorkers is the sweep's pool size (KRYPTKEEPER_RENEWAL_WORKERS). It
// sits above the default connector cap (10) on purpose: the cap, not the
// pool, is the limiter for issuance; the install leg is not capped.
func renewalWorkers() int {
	if raw := strings.TrimSpace(os.Getenv("KRYPTKEEPER_RENEWAL_WORKERS")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 1 {
			return n
		}
		logging.Infof("renewal scheduler: invalid KRYPTKEEPER_RENEWAL_WORKERS=%q, using %d", raw, defaultRenewalWorkers)
	}
	return defaultRenewalWorkers
}

// tickJitterPercent reads RENEWAL_TICK_JITTER_PERCENT: default 10, 0 disables,
// capped at 10 so jitter can never stretch the cadence by more than a tenth.
func tickJitterPercent() int {
	raw := strings.TrimSpace(os.Getenv("RENEWAL_TICK_JITTER_PERCENT"))
	if raw == "" {
		return maxTickJitterPercent
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		logging.Infof("renewal scheduler: invalid RENEWAL_TICK_JITTER_PERCENT=%q, using %d", raw, maxTickJitterPercent)
		return maxTickJitterPercent
	}
	if n > maxTickJitterPercent {
		n = maxTickJitterPercent
	}
	return n
}

// jitterFor is deterministic per key and seed: a fresh random each tick would
// make a certificate's "due yet?" answer flap between ticks. It is always
// below jitterPercent of window; zero when jitter is disabled (the zero value,
// so struct-literal schedulers in tests are unaffected).
func (s *RenewalScheduler) jitterFor(key string, window time.Duration) time.Duration {
	maxJitter := window / 100 * time.Duration(s.jitterPercent)
	if maxJitter <= 0 {
		return 0
	}
	h := fnv.New64a()
	fmt.Fprintf(h, "%d|%s", s.jitterSeed, key)
	return time.Duration(h.Sum64() % uint64(maxJitter))
}

// --- queue state ---

// renewalQueueState is read by the SLO handler, which is registered without
// the scheduler instance (same package-level pattern as renewalStatusHolder).
var renewalQueueState struct {
	mu         sync.Mutex
	depth      int
	workers    int
	avgJobSecs float64
	finished   int
}

func queueSetDepth(depth, workers int) {
	renewalQueueState.mu.Lock()
	renewalQueueState.depth, renewalQueueState.workers = depth, workers
	renewalQueueState.mu.Unlock()
}

func queueJobDone(d time.Duration) {
	renewalQueueState.mu.Lock()
	defer renewalQueueState.mu.Unlock()
	if renewalQueueState.depth > 0 {
		renewalQueueState.depth--
	}
	secs := d.Seconds()
	if renewalQueueState.finished == 0 {
		renewalQueueState.avgJobSecs = secs
	} else {
		renewalQueueState.avgJobSecs = 0.2*secs + 0.8*renewalQueueState.avgJobSecs
	}
	renewalQueueState.finished++
}

// RenewalQueueReport is the `queue` object on GET /reports/renewal-slo.
// ConnectorBudgets repeats Connectors in the compact shape the Automation
// page (W27-20) renders.
type RenewalQueueReport struct {
	Depth            int                         `json:"depth"`
	ETASeconds       int                         `json:"eta_seconds"`
	ETAKnown         bool                        `json:"eta_known"`
	Workers          int                         `json:"workers"`
	Connectors       []connectors.ThrottleStatus `json:"connectors"`
	ConnectorBudgets []RenewalConnectorBudget    `json:"connector_budgets"`
}

type RenewalConnectorBudget struct {
	ConnectorID string `json:"connector_id"`
	InFlight    int    `json:"in_flight"`
	Cap         int    `json:"cap"`
	DailyUsed   int    `json:"daily_used,omitempty"`
	DailyLimit  int    `json:"daily_limit,omitempty"`
}

func renewalQueueReport(th *connectors.Throttle) RenewalQueueReport {
	renewalQueueState.mu.Lock()
	depth, workers, avg, finished := renewalQueueState.depth, renewalQueueState.workers, renewalQueueState.avgJobSecs, renewalQueueState.finished
	renewalQueueState.mu.Unlock()

	conns := th.Snapshot()
	budgets := make([]RenewalConnectorBudget, 0, len(conns))
	capSum := 0
	for _, c := range conns {
		budgets = append(budgets, RenewalConnectorBudget{ConnectorID: c.ConnectorID, InFlight: c.InFlight,
			Cap: c.MaxConcurrent, DailyUsed: c.DailyUsed, DailyLimit: c.DailyBudget})
		capSum += c.MaxConcurrent
	}
	if workers == 0 {
		workers = renewalWorkers()
	}
	rep := RenewalQueueReport{Depth: depth, Workers: workers, ETAKnown: finished > 0, Connectors: conns, ConnectorBudgets: budgets}
	if rep.ETAKnown && depth > 0 {
		parallel := workers
		if capSum > 0 && capSum < parallel {
			parallel = capSum
		}
		rep.ETASeconds = int(math.Ceil(float64(depth)/float64(parallel)) * avg)
	}
	return rep
}

// --- worker pool ---

type renewalJob struct {
	cert   CertificateItem
	expiry time.Time
}

type renewalJobTotals struct {
	pending, gaveUp, renewed, notifications int
}

// stopping reports a requested shutdown. Workers check it before STARTING a
// job, never mid-job: a renewal's private key exists only in memory between
// issuance and install, so abandoning one after the CA minted its certificate
// leaves a successor nothing can ever install and the next tick issues again
// (the duplicate issuance W27-34 measured across a restart).
func (s *RenewalScheduler) stopping() bool {
	select {
	case <-s.stop:
		return true
	default:
		return false
	}
}

const (
	defaultShutdownDrain = 8 * time.Second
	envShutdownDrain     = "KRYPTKEEPER_SHUTDOWN_DRAIN"
)

// shutdownDrainTimeout bounds how long Stop waits for renewals already
// running. The default stays under the 10 s a container runtime grants before
// SIGKILL; raise it together with the runtime's stop timeout.
func shutdownDrainTimeout() time.Duration {
	if raw := strings.TrimSpace(os.Getenv(envShutdownDrain)); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil && d >= 0 {
			return d
		}
		logging.Infof("renewal scheduler: invalid %s=%q, using %s", envShutdownDrain, raw, defaultShutdownDrain)
	}
	return defaultShutdownDrain
}

// drainScans waits for in-progress ticks to finish their running jobs (the
// workers start no new ones once stop is closed) or for timeout.
func (s *RenewalScheduler) drainScans(timeout time.Duration) {
	if s.scansRunning.Load() == 0 {
		return
	}
	deadline := time.Now().Add(timeout)
	for s.scansRunning.Load() > 0 {
		if time.Now().After(deadline) {
			logging.Infof("renewal scheduler: stop gave up waiting %s for in-flight renewals", timeout)
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// runRenewalJobs executes the sweep's candidates through a bounded pool, most
// urgent expiry first. A cancelled context stops dispatch; the jobs it
// skipped count as pending and write no failure audit.
func (s *RenewalScheduler) runRenewalJobs(ctx context.Context, jobs []renewalJob, idx *bindingSweepIndex, now time.Time, pol retryPolicy, cooldown time.Duration) renewalJobTotals {
	sort.SliceStable(jobs, func(i, j int) bool { return jobs[i].expiry.Before(jobs[j].expiry) })
	workers := renewalWorkers()
	queueSetDepth(len(jobs), workers)
	defer queueSetDepth(0, workers)

	var (
		mu     sync.Mutex
		totals renewalJobTotals
		wg     sync.WaitGroup
	)
	ch := make(chan renewalJob)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range ch {
				if ctx.Err() != nil || s.stopping() {
					mu.Lock()
					totals.pending++
					mu.Unlock()
					queueJobDone(0)
					continue
				}
				started := time.Now()
				t := s.runRenewalJob(ctx, job, idx, now, pol, cooldown)
				queueJobDone(time.Since(started))
				mu.Lock()
				totals.pending += t.pending
				totals.gaveUp += t.gaveUp
				totals.renewed += t.renewed
				totals.notifications += t.notifications
				mu.Unlock()
			}
		}()
	}
	for _, job := range jobs {
		ch <- job
	}
	close(ch)
	wg.Wait()
	return totals
}

// runRenewalJob is one certificate's post-selection work: the bound-target
// sweep, then the owner reminder the old serial loop sent inline.
func (s *RenewalScheduler) runRenewalJob(ctx context.Context, job renewalJob, idx *bindingSweepIndex, now time.Time, pol retryPolicy, cooldown time.Duration) renewalJobTotals {
	var t renewalJobTotals
	res := s.sweepBoundTargets(ctx, idx, job.cert, now, pol)
	t.pending, t.gaveUp, t.renewed = res.pending, res.gaveUp, res.renewed
	if res.allRenewed() {
		return t // renewed+installed everywhere; no reminder needed this tick
	}
	c := cooldown
	// Execution failed, is backing off or was refused: the owner still gets
	// the expiry reminder -- an armed sweep must never LOSE alerts. A final
	// failure forces the reminder past the cooldown: nothing else will follow.
	if res.owed > 0 && res.finalFailure {
		c = 0
	}
	if s.handleRenewalCandidate(ctx, job.cert, job.expiry, now, c) {
		t.notifications++
	}
	return t
}

// --- rate-limit deferral and audit ---

// deferredOutcome turns an issuance error that is not a real failure into a
// pending outcome: an upstream/local rate limit (audited as a deferral) or a
// cancelled sweep context. Neither is audited as renew_execute_failed|partial,
// the only actions installState counts, so neither burns an attempt.
func (s *RenewalScheduler) deferredOutcome(ctx context.Context, cert CertificateItem, target ManagedTarget, err error) (autoRenewOutcome, bool) {
	var rl *connectors.RateLimitError
	if errors.As(err, &rl) {
		s.emitRenewalAudit(ctx, cert, renewalDeferredAction, AuditOutcomeSkipped,
			fmt.Sprintf("target_id=%s reason=%s retry_after=%s", target.ID, rl.Reason, rl.RetryAfter.Round(time.Second)))
		return autoRenewOutcome{pending: true}, true
	}
	if ctx.Err() != nil {
		return autoRenewOutcome{pending: true}, true
	}
	return autoRenewOutcome{}, false
}

// installThrottleObserver audits every upstream 429 the shared throttle sees.
func (s *RenewalScheduler) installThrottleObserver() {
	if s.auditProvider == nil {
		return
	}
	connectors.DefaultThrottle.SetObserver(func(ev connectors.ThrottleEvent) {
		entry := AuditEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339), Action: connectorRateLimited,
			ActorType: "system", ActorID: "connector-throttle", ResourceType: "connector", ResourceID: ev.ConnectorID,
			Outcome:       AuditOutcomeDenied,
			ChangeSummary: fmt.Sprintf("reason=%s retry_after=%s failures=%d", ev.Reason, ev.RetryAfter.Round(time.Second), ev.Failures),
		}
		if err := s.auditProvider.AppendEntry(context.Background(), entry); err != nil {
			logging.Warnf("renewal scheduler: audit append failed: %v", err)
		}
	})
}
