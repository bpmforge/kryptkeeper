// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package connectors

import (
	"context"
	"time"
)

// W27-34 follow-up: the upstream gate.
//
// golang.org/x/crypto/acme retries a 429 itself, inside one Issue call, until
// the request context ends. The throttle's post-release backoff therefore
// never sees an ACME rate limit, and every sibling job keeps sending orders
// into a CA that has just said "wait". The gate closes that: a connector
// reports each Retry-After it observes (NoteRetryAfter) and parks the next
// rate-limited request (Wait) until the connector-wide hold has elapsed.
//
// The hold is a soft pause, distinct from the post-release backoff: waiters
// sleep through it rather than being refused, because the upstream named an
// exact moment at which it will accept requests again.

type gateCtxKey struct{}
type drainCtxKey struct{}

// WithDrain marks ctx's issuances as shutting down once ch is closed: gate
// waits return at once and the ACME client stops retrying a 429, so a graceful
// stop never sleeps through an upstream hold. Work already past its rate-limited
// request is not touched.
func WithDrain(ctx context.Context, ch <-chan struct{}) context.Context {
	return context.WithValue(ctx, drainCtxKey{}, ch)
}

// UpstreamGate is one connector's view of its throttle for the duration of an
// Issue call. The zero/nil gate is inert, so connectors work outside a Registry.
type UpstreamGate struct {
	t     *Throttle
	id    string
	drain <-chan struct{}
}

// UpstreamGateFrom returns the gate Registry.Issue attached to ctx, or nil.
func UpstreamGateFrom(ctx context.Context) *UpstreamGate {
	g, _ := ctx.Value(gateCtxKey{}).(*UpstreamGate)
	return g
}

func (r *Registry) withGate(ctx context.Context, t *Throttle, id string) context.Context {
	d, _ := ctx.Value(drainCtxKey{}).(<-chan struct{})
	return context.WithValue(ctx, gateCtxKey{}, &UpstreamGate{t: t, id: id, drain: d})
}

// NoteRetryAfter records that the upstream asked every caller to wait d.
func (g *UpstreamGate) NoteRetryAfter(d time.Duration) {
	if g == nil || d <= 0 {
		return
	}
	until := g.t.hold(g.id, d)
	g.t.persistGate(g.id, until, gateReasonRetryAfter)
}

// Draining reports whether the process is shutting down.
func (g *UpstreamGate) Draining() bool {
	if g == nil || g.drain == nil {
		return false
	}
	select {
	case <-g.drain:
		return true
	default:
		return false
	}
}

// Wait blocks while the connector is on an upstream hold. It returns a
// RateLimitError when the process starts draining and ctx's error when ctx
// ends first.
func (g *UpstreamGate) Wait(ctx context.Context) error {
	if g == nil {
		return nil
	}
	for {
		g.t.syncGate(ctx, g.id)
		rem := g.t.holdRemaining(g.id)
		if rem <= 0 {
			return nil
		}
		if g.Draining() {
			return &RateLimitError{ConnectorID: g.id, Reason: "shutdown", RetryAfter: rem}
		}
		timer := time.NewTimer(rem)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-g.drain: // nil channel when not draining-aware: blocks forever, as intended
			timer.Stop()
		}
	}
}

func (t *Throttle) hold(id string, d time.Duration) time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	s := t.stateLocked(id, now)
	if until := now.Add(d); until.After(s.holdUntil) {
		s.holdUntil = until
	}
	return s.holdUntil
}

func (t *Throttle) holdRemaining(id string) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	return t.stateLocked(id, now).holdUntil.Sub(now)
}
