// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"math/rand/v2"
	"sync"
	"time"

	"kryptkeeper/internal/agentclient"
)

const (
	renewBackoffBase = time.Minute
	renewBackoffMax  = time.Hour
)

// renewGuard keeps renewals from overlapping and spaces out retries of a
// failing one. The hub re-queues a task until a result is reported and
// re-tasks a failed one on the next inventory, so without this each poll
// started another ACME order; the second one found :80 still held by the
// first's HTTP-01 listener. At most one renewal runs at a time across all
// tasks, because every HTTP-01 attempt needs the same :80.
type renewGuard struct {
	mu      sync.Mutex
	now     func() time.Time
	jitter  func(time.Duration) time.Duration
	running bool
	retries map[string]*renewRetry
}

type renewRetry struct {
	failures int
	next     time.Time
}

func newRenewGuard() *renewGuard {
	return &renewGuard{
		now: time.Now,
		// +-20% so agents that failed together do not retry in lockstep.
		jitter: func(d time.Duration) time.Duration {
			return time.Duration(float64(d) * (0.8 + 0.4*rand.Float64()))
		},
		retries: map[string]*renewRetry{},
	}
}

// renewKey identifies the certificate a task renews. The fingerprint is
// preferred: the hub issues a fresh task ID when it re-tasks a failed
// renewal, but the expiring certificate stays the same.
func renewKey(t agentclient.RenewalTask) string {
	if t.Fingerprint != "" {
		return "fp:" + t.Fingerprint
	}
	return "id:" + t.TaskID
}

// start reserves the single renewal slot for key. It reports false while
// another renewal runs or key is still backing off.
func (g *renewGuard) start(key string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.running {
		return false
	}
	if r, ok := g.retries[key]; ok && g.now().Before(r.next) {
		return false
	}
	g.running = true
	return true
}

// finish releases the slot. A failure schedules the next attempt at
// base*2^(failures-1), capped at the maximum, with jitter; success clears
// the history.
func (g *renewGuard) finish(key string, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.running = false
	if err == nil {
		delete(g.retries, key)
		return
	}
	r := g.retries[key]
	if r == nil {
		r = &renewRetry{}
		g.retries[key] = r
	}
	r.failures++
	d := renewBackoffBase
	for i := 1; i < r.failures && d < renewBackoffMax; i++ {
		d *= 2
	}
	d = min(d, renewBackoffMax)
	r.next = g.now().Add(g.jitter(d))
}

// dispatchRenewals starts run for each renew task the guard admits. The run
// executes in its own goroutine; the slot is released when it returns.
func (g *renewGuard) dispatchRenewals(tasks []agentclient.RenewalTask, run func(agentclient.RenewalTask) error) {
	for _, task := range tasks {
		if task.Action != "renew" {
			continue
		}
		key := renewKey(task)
		if !g.start(key) {
			continue
		}
		go func() { g.finish(key, run(task)) }()
	}
}
