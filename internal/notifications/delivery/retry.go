// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package delivery

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/logging"
)

// Delivery statuses. "retrying" is non-final: the entry is persisted with the
// time of its next attempt.
const (
	StatusSent     = "sent"
	StatusFailed   = "failed"
	StatusRetrying = "retrying"
)

// Policy bounds the retries wrapped around every channel (W32-31, UC-K04).
type Policy struct {
	MaxAttempts int           // total attempts including the first
	Base        time.Duration // delay before attempt 2; doubles each attempt
	Cap         time.Duration // upper bound on any delay, Retry-After included
	Jitter      float64       // +/- fraction applied to each delay (0..1)
	// Lease is how long a claimed entry stays invisible to other claimers, so
	// a crash mid-send makes it due again instead of stranding it.
	Lease time.Duration
}

// DefaultPolicy is 8 attempts, 1 min base, 1 h cap, 20% jitter.
func DefaultPolicy() Policy {
	return Policy{MaxAttempts: 8, Base: time.Minute, Cap: time.Hour, Jitter: 0.2, Lease: 2 * time.Minute}
}

func (p Policy) normalized() Policy {
	d := DefaultPolicy()
	if p.MaxAttempts <= 0 {
		p.MaxAttempts = d.MaxAttempts
	}
	if p.Base <= 0 {
		p.Base = d.Base
	}
	if p.Cap <= 0 {
		p.Cap = d.Cap
	}
	if p.Cap < p.Base {
		p.Cap = p.Base
	}
	if p.Jitter < 0 || p.Jitter > 1 {
		p.Jitter = d.Jitter
	}
	if p.Lease <= 0 {
		p.Lease = d.Lease
	}
	return p
}

// RetryAfterError is returned by a channel whose receiver asked it to back
// off (HTTP 429/503 Retry-After). The retrier honours it, capped by Policy.Cap.
type RetryAfterError struct {
	After time.Duration
	Err   error
}

func (e *RetryAfterError) Error() string { return e.Err.Error() }
func (e *RetryAfterError) Unwrap() error { return e.Err }

// RetryAfter extracts a receiver-requested delay from err.
func RetryAfter(err error) (time.Duration, bool) {
	var ra *RetryAfterError
	if errors.As(err, &ra) && ra.After > 0 {
		return ra.After, true
	}
	return 0, false
}

// parseRetryAfter reads an HTTP Retry-After header: delta-seconds or an
// HTTP-date (RFC 9110 section 10.2.3).
func parseRetryAfter(h string, now time.Time) (time.Duration, bool) {
	h = strings.TrimSpace(h)
	if h == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(h); err == nil {
		if secs <= 0 {
			return 0, false
		}
		return time.Duration(secs) * time.Second, true
	}
	if t, err := http.ParseTime(h); err == nil {
		if d := t.Sub(now); d > 0 {
			return d, true
		}
	}
	return 0, false
}

// Entry is one delivery's durable retry state.
type Entry struct {
	ID            string
	Event         Event
	Attempts      int
	NextAttemptAt time.Time
	Status        string // retrying | sent | failed
	LastError     string
}

// Store persists retry state so a restart resumes pending deliveries.
type Store interface {
	Put(ctx context.Context, e Entry) error
	// ClaimDue returns up to limit retrying entries whose NextAttemptAt <= now,
	// atomically incrementing Attempts and pushing NextAttemptAt to now+lease.
	ClaimDue(ctx context.Context, now time.Time, lease time.Duration, limit int) ([]Entry, error)
	Update(ctx context.Context, e Entry) error
	// Prune drops settled (sent or failed) entries last touched before t.
	Prune(ctx context.Context, before time.Time) error
}

// Retrier wraps any Channel's Send with persisted retries. It depends only on
// the Channel interface, so built-in, ITSM and plugin channels (W38-02) all
// get identical behaviour with no per-type code.
type Retrier struct {
	channels map[string]Channel
	store    Store
	policy   Policy
	now      func() time.Time
	rnd      func() float64

	// OnSettled is told of every final outcome (sent or failed), including
	// those reached after a restart. It must not block for long.
	OnSettled func(ctx context.Context, ev Event, res Result)

	mu      sync.Mutex
	results []Result
}

// NewRetrier builds a retrier. A nil store gets an in-memory one (no restart
// resume). now==nil uses time.Now.
func NewRetrier(channels []Channel, policy Policy, store Store, now func() time.Time) *Retrier {
	m := make(map[string]Channel, len(channels))
	for _, ch := range channels {
		m[ch.Name()] = ch
	}
	if store == nil {
		store = NewMemStore()
	}
	if now == nil {
		now = time.Now
	}
	return &Retrier{channels: m, store: store, policy: policy.normalized(), now: now, rnd: rand.Float64}
}

// SetRandom replaces the jitter source (tests).
func (r *Retrier) SetRandom(f func() float64) { r.rnd = f }

// backoff is the delay before the attempt after attempt n (1-based):
// Base*2^(n-1), jittered, never above Cap.
func (r *Retrier) backoff(n int) time.Duration {
	d := float64(r.policy.Base) * math.Pow(2, float64(n-1))
	if d > float64(r.policy.Cap) {
		d = float64(r.policy.Cap)
	}
	d *= 1 + r.policy.Jitter*(2*r.rnd()-1)
	if d > float64(r.policy.Cap) {
		d = float64(r.policy.Cap)
	}
	if d < 0 {
		d = 0
	}
	return time.Duration(d)
}

// Deliver makes the first attempt now. The result is sent, failed, or
// retrying (persisted; Run/Process continues it).
func (r *Retrier) Deliver(ctx context.Context, ev Event) Result {
	if _, ok := r.channels[ev.Channel]; !ok {
		res := Result{EventID: ev.ID, Channel: ev.Channel, Status: StatusFailed,
			Error: fmt.Sprintf("unknown channel: %s", ev.Channel), DeliveredAt: r.now().UTC()}
		r.record(res)
		r.settle(ctx, ev, res)
		return res
	}
	now := r.now()
	e := Entry{ID: ev.ID, Event: ev, Attempts: 1, NextAttemptAt: now.Add(r.policy.Lease), Status: StatusRetrying}
	if err := r.store.Put(ctx, e); err != nil {
		// Without durable state we still try once: losing the alert is worse
		// than losing its retries.
		logging.Warnf("delivery retry store unavailable, sending without retry state: %v", err)
	}
	return r.attempt(ctx, e)
}

// Process attempts every entry that is due. It returns how many it attempted.
func (r *Retrier) Process(ctx context.Context) (int, error) {
	due, err := r.store.ClaimDue(ctx, r.now(), r.policy.Lease, 100)
	if err != nil {
		return 0, err
	}
	for _, e := range due {
		r.attempt(ctx, e)
	}
	return len(due), nil
}

// Run polls Process until ctx ends, and prunes settled rows daily.
func (r *Retrier) Run(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = 5 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	lastPrune := r.now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if _, err := r.Process(ctx); err != nil {
			logging.Warnf("delivery retry: processing due entries: %v", err)
		}
		if r.now().Sub(lastPrune) >= 24*time.Hour {
			lastPrune = r.now()
			if err := r.store.Prune(ctx, r.now().Add(-14*24*time.Hour)); err != nil {
				logging.Warnf("delivery retry: prune: %v", err)
			}
		}
	}
}

// Results returns every final outcome recorded by this process.
func (r *Retrier) Results() []Result {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Result(nil), r.results...)
}

func (r *Retrier) record(res Result) {
	r.mu.Lock()
	r.results = append(r.results, res)
	r.mu.Unlock()
}

func (r *Retrier) settle(ctx context.Context, ev Event, res Result) {
	if r.OnSettled != nil {
		r.OnSettled(ctx, ev, res)
	}
}

// attempt sends e.Event once (e.Attempts already counts this try) and persists
// the outcome.
func (r *Retrier) attempt(ctx context.Context, e Entry) Result {
	ch, ok := r.channels[e.Event.Channel]
	if !ok { // channel removed from config while the entry waited
		return r.finish(ctx, e, StatusFailed, "unknown channel: "+e.Event.Channel)
	}
	err := ch.Send(ctx, e.Event)
	if err == nil {
		return r.finish(ctx, e, StatusSent, "")
	}
	msg := RedactURLs(err.Error())
	logging.Warnf("delivery attempt %d/%d for event %s on channel %s failed: %s",
		e.Attempts, r.policy.MaxAttempts, e.ID, e.Event.Channel, msg)
	if e.Attempts >= r.policy.MaxAttempts {
		return r.finish(ctx, e, StatusFailed, msg)
	}
	delay := r.backoff(e.Attempts)
	if ra, ok := RetryAfter(err); ok {
		if ra > r.policy.Cap {
			ra = r.policy.Cap // a hostile receiver cannot park an alert for days
		}
		if ra > delay {
			delay = ra
		}
	}
	e.NextAttemptAt, e.Status, e.LastError = r.now().Add(delay), StatusRetrying, msg
	if uerr := r.store.Update(ctx, e); uerr != nil {
		logging.Warnf("delivery retry: persisting next attempt for %s: %v", e.ID, uerr)
	}
	return Result{EventID: e.ID, Channel: e.Event.Channel, Status: StatusRetrying, Error: msg, Attempts: e.Attempts}
}

func (r *Retrier) finish(ctx context.Context, e Entry, status, msg string) Result {
	e.Status, e.LastError = status, msg
	if err := r.store.Update(ctx, e); err != nil {
		logging.Warnf("delivery retry: persisting outcome for %s: %v", e.ID, err)
	}
	res := Result{EventID: e.ID, Channel: e.Event.Channel, Status: status, Error: msg, DeliveredAt: r.now().UTC(), Attempts: e.Attempts}
	r.record(res)
	r.settle(ctx, e.Event, res)
	return res
}

// MemStore is the in-memory Store: retries work within one process lifetime.
type MemStore struct {
	mu      sync.Mutex
	entries map[string]Entry
	touched map[string]time.Time
}

func NewMemStore() *MemStore {
	return &MemStore{entries: map[string]Entry{}, touched: map[string]time.Time{}}
}

func (m *MemStore) Put(_ context.Context, e Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[e.ID] = e
	m.touched[e.ID] = time.Now()
	return nil
}

func (m *MemStore) Update(ctx context.Context, e Entry) error { return m.Put(ctx, e) }

func (m *MemStore) ClaimDue(_ context.Context, now time.Time, lease time.Duration, limit int) ([]Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Entry
	for id, e := range m.entries {
		if len(out) >= limit {
			break
		}
		if e.Status != StatusRetrying || e.NextAttemptAt.After(now) {
			continue
		}
		e.Attempts++
		e.NextAttemptAt = now.Add(lease)
		m.entries[id] = e
		out = append(out, e)
	}
	return out, nil
}

func (m *MemStore) Prune(_ context.Context, before time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, e := range m.entries {
		if e.Status != StatusRetrying && m.touched[id].Before(before) {
			delete(m.entries, id)
			delete(m.touched, id)
		}
	}
	return nil
}
