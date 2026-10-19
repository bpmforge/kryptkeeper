// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"kryptkeeper/internal/logging"
	"math/rand/v2"
	"net"
	"strings"
	"sync"
	"syscall"
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
	// preflight, when set, runs after a renewal slot is reserved and before the
	// renewal starts; an error skips this attempt and backs it off like any
	// failed renewal. nil (the default) means no probe.
	preflight func() error
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
		if g.preflight != nil {
			if err := g.preflight(); err != nil {
				g.finish(key, err)
				logging.Infof("renew %s skipped: %v", key, err)
				continue
			}
		}
		go func() { g.finish(key, run(task)) }()
	}
}

// probeHTTP01Port tries to bind addr's port on each IP family and closes
// immediately. With an empty host it probes tcp4 0.0.0.0 and tcp6 [::]
// separately: on Windows a single dual-stack bind does not see an IPv4-only
// holder (UC-C05 F1). A family the host lacks is skipped; the error text
// matches the ACME renewer's so operators see one message.
func probeHTTP01Port(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("probe HTTP-01 port: %w", err)
	}
	type family struct{ network, label, host string }
	families := []family{{"tcp4", "IPv4", host}, {"tcp6", "IPv6", host}}
	if host == "" {
		families[0].host, families[1].host = "0.0.0.0", "::"
	}
	bound := 0
	for _, f := range families {
		ln, err := net.Listen(f.network, net.JoinHostPort(f.host, port))
		if err != nil {
			if familyUnsupported(err) {
				continue
			}
			return fmt.Errorf("cannot listen on %s for the ACME HTTP-01 challenge: port 80 in use or not permitted; see docs/ops/WINDOWS_AGENT.md: %s listener holds :%s: %w",
				addr, f.label, port, err)
		}
		_ = ln.Close()
		bound++
	}
	if bound == 0 {
		return fmt.Errorf("cannot listen on %s for the ACME HTTP-01 challenge: port 80 in use or not permitted; see docs/ops/WINDOWS_AGENT.md: no usable IP family", addr)
	}
	return nil
}

// familyUnsupported reports an IP family the host lacks (e.g. IPv6 disabled).
// 10047 is Windows WSAEAFNOSUPPORT, which syscall.EAFNOSUPPORT does not match
// there.
func familyUnsupported(err error) bool {
	if errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EADDRNOTAVAIL) {
		return true
	}
	var en syscall.Errno
	if errors.As(err, &en) && uintptr(en) == 10047 {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "address family not supported")
}
