// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package connectors

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"kryptkeeper/internal/logging"
)

// W35-01 / W27-39: persistence seams. This package stays free of database
// code; internal/bootstrap implements both interfaces on the core DB.

// RetryGateStore holds each connector's upstream hold so it survives a restart
// and is shared by replicas. Save must keep the LATER of the stored and given
// deadline (replicas race), and Load returns the zero time when nothing is held.
type RetryGateStore interface {
	Load(ctx context.Context, id string) (time.Time, error)
	Save(ctx context.Context, id string, until time.Time, reason string) error
}

// Stored hold reasons: "retry_after" is the soft upstream gate (waiters
// sleep); "backoff" is the post-429 refusal window.
const (
	gateReasonRetryAfter = "retry_after"
	gateReasonBackoff    = "backoff"
)

// IssueLogStore is the append-only record of admitted orders behind the rolling
// window budget. Since returns the order times after since, oldest first.
type IssueLogStore interface {
	Append(ctx context.Context, id string, at time.Time) error
	Since(ctx context.Context, id string, since time.Time) ([]time.Time, error)
	Prune(ctx context.Context, id string, before time.Time) error
}

const (
	storeTimeout   = 3 * time.Second
	storeWarnEvery = 30 * time.Second
	maxWindow      = 30 * 24 * time.Hour
)

// SetStores injects the persistence backends; either may be nil (memory only).
func (t *Throttle) SetStores(gate RetryGateStore, log IssueLogStore) {
	t.mu.Lock()
	t.gateStore, t.logStore = gate, log
	t.mu.Unlock()
}

// warnStore logs a store failure at most once per storeWarnEvery per kind, so a
// database outage is visible without a line per order.
func (t *Throttle) warnStore(kind string, err error) {
	t.mu.Lock()
	now := t.now()
	if last, ok := t.storeWarned[kind]; ok && now.Sub(last) < storeWarnEvery {
		t.mu.Unlock()
		return
	}
	t.storeWarned[kind] = now
	t.mu.Unlock()
	logging.Warnf("connectors: %s store unavailable, continuing with the in-memory state only: %v", kind, err)
}

// syncGate merges the stored hold into the in-memory soft hold (the Wait path). It runs outside t.mu: a database
// call must never sit under the admission lock. Fail open: if the store cannot
// be read the in-memory state still applies. Failing closed would stop every
// expiring certificate's renewal on a database blip, whereas the worst
// fail-open outcome is an order the CA answers with another 429, which the
// in-memory hold then catches.
func (t *Throttle) syncGate(ctx context.Context, id string) {
	t.mu.Lock()
	gs := t.gateStore
	t.mu.Unlock()
	if gs == nil {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()
	until, err := gs.Load(cctx, id)
	if err != nil {
		t.warnStore("retry gate", err)
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	if !until.After(now) {
		return
	}
	s := t.stateLocked(id, now)
	if until.After(s.holdUntil) {
		s.holdUntil = until
	}
}

// persistGate writes a deadline through to the store, best effort.
func (t *Throttle) persistGate(id string, until time.Time, reason string) {
	t.mu.Lock()
	gs := t.gateStore
	t.mu.Unlock()
	if gs == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
	defer cancel()
	if err := gs.Save(ctx, id, until, reason); err != nil {
		t.warnStore("retry gate", err)
	}
}

// syncBackoff loads the stored deadline for acquire's refusal path: a hold
// saved by a previous process or another replica must stop admission here as
// it did where the 429 was seen.
func (t *Throttle) syncBackoff(ctx context.Context, id string) {
	t.mu.Lock()
	gs := t.gateStore
	t.mu.Unlock()
	if gs == nil {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()
	until, err := gs.Load(cctx, id)
	if err != nil {
		t.warnStore("retry gate", err)
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	if !until.After(now) {
		return
	}
	s := t.stateLocked(id, now)
	// Only a deadline this process does not already know (a restart's
	// leftover or a replica's 429) becomes a refusal: this process's own soft
	// hold must keep parking siblings rather than refusing them.
	if until.After(s.holdUntil) && until.After(s.blockedUntil) {
		s.blockedUntil = until
	}
}

// hydrateWindow loads the order log for id once, so a restarted process knows
// what the previous one already sent. A failed load is retried on the next
// admission and meanwhile counts from empty (fail open, as for the gate).
func (t *Throttle) hydrateWindow(ctx context.Context, id string) {
	t.mu.Lock()
	now := t.now()
	ls := t.logStore
	lim := t.limitsLocked(id)
	s := t.stateLocked(id, now)
	need := ls != nil && lim.Window > 0 && lim.WindowBudget > 0 && !s.windowLoaded
	t.mu.Unlock()
	if !need {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()
	rows, err := ls.Since(cctx, id, now.Add(-lim.Window))
	if err != nil {
		t.warnStore("issue log", err)
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	s = t.stateLocked(id, t.now())
	if !s.windowLoaded {
		// Merge, not replace: orders admitted while the load ran are in memory.
		merged := append(append([]time.Time{}, rows...), s.issued...)
		sort.Slice(merged, func(i, j int) bool { return merged[i].Before(merged[j]) })
		s.issued = merged
		s.windowLoaded = true
	}
}

// persistIssue appends an admitted order to the durable log and prunes rows
// that have left the window.
func (t *Throttle) persistIssue(id string, at time.Time, window time.Duration) {
	t.mu.Lock()
	ls := t.logStore
	t.mu.Unlock()
	if ls == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
	defer cancel()
	if err := ls.Append(ctx, id, at); err != nil {
		t.warnStore("issue log", err)
		return
	}
	if err := ls.Prune(ctx, id, at.Add(-window)); err != nil {
		t.warnStore("issue log", err)
	}
}

// windowTrim drops orders that have left the window ending at now. An order
// leaves exactly Window after it was sent: one sent at t0 frees its slot at
// t0+Window.
func windowTrim(issued []time.Time, now time.Time, window time.Duration) []time.Time {
	cutoff := now.Add(-window)
	i := 0
	for i < len(issued) && !issued[i].After(cutoff) {
		i++
	}
	return issued[i:]
}

type windowCfg struct {
	window time.Duration
	budget int
}

// ConfigureWindow sets a connector's window from its config_json
// (rate_window / rate_budget). The operator's KRYPTKEEPER_CONNECTOR_LIMITS
// entry for the same connector wins; this never overrides it.
func (t *Throttle) ConfigureWindow(id string, window time.Duration, budget int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if window <= 0 || budget <= 0 {
		delete(t.cfgWin, id)
		return
	}
	t.cfgWin[id] = windowCfg{window, budget}
}

// ParseWindow reads a window given as a Go duration string ("1h") or a number
// of seconds. Zero, negative, unparsable and over-30-day values are rejected;
// an absent value is 0 with no error.
func ParseWindow(raw json.RawMessage) (time.Duration, error) {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" {
		return 0, nil
	}
	var d time.Duration
	if strings.HasPrefix(s, `"`) {
		var str string
		if err := json.Unmarshal(raw, &str); err != nil {
			return 0, err
		}
		pd, err := time.ParseDuration(strings.TrimSpace(str))
		if err != nil {
			return 0, err
		}
		d = pd
	} else {
		var secs float64
		if err := json.Unmarshal(raw, &secs); err != nil {
			return 0, err
		}
		d = time.Duration(secs * float64(time.Second))
	}
	if d <= 0 || d > maxWindow {
		return 0, fmt.Errorf("window %s outside (0, %s]", d, maxWindow)
	}
	return d, nil
}
