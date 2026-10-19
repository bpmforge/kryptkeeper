// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package certmanagerissuer

import (
	"sync"
	"time"
)

const (
	backoffBase = 2 * time.Second
	backoffCap  = 5 * time.Minute
)

// backoffEntry tracks retry state for one CertificateRequest.
type backoffEntry struct {
	namespace, name string
	failures        int
	next            time.Time
	inflight        bool
}

// backoff is a tiny per-key exponential backoff (2 s, 4 s, ... capped at
// 5 min) that also guards against concurrent processing of the same key.
type backoff struct {
	mu      sync.Mutex
	entries map[string]*backoffEntry
}

func newBackoff() *backoff {
	return &backoff{entries: map[string]*backoffEntry{}}
}

// delayFor returns the wait after the nth consecutive failure (n >= 1).
func delayFor(failures int) time.Duration {
	d := backoffBase
	for i := 1; i < failures; i++ {
		d *= 2
		if d >= backoffCap {
			return backoffCap
		}
	}
	return d
}

// begin claims key for processing. It returns false when the key is still in
// backoff or is already being processed.
func (b *backoff) begin(key, ns, name string, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	e := b.entries[key]
	if e == nil {
		e = &backoffEntry{namespace: ns, name: name}
		b.entries[key] = e
	}
	if e.inflight || now.Before(e.next) {
		return false
	}
	e.inflight = true
	return true
}

// end releases a claim taken by begin and drops entries with no pending retry.
func (b *backoff) end(key string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	e := b.entries[key]
	if e == nil {
		return
	}
	e.inflight = false
	if e.failures == 0 {
		delete(b.entries, key)
	}
}

// fail records a failure and returns the delay before the next attempt.
func (b *backoff) fail(key, ns, name string, now time.Time) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	e := b.entries[key]
	if e == nil {
		e = &backoffEntry{namespace: ns, name: name}
		b.entries[key] = e
	}
	e.failures++
	d := delayFor(e.failures)
	e.next = now.Add(d)
	return d
}

// reset clears the failure history of key (success or terminal outcome).
func (b *backoff) reset(key string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if e := b.entries[key]; e != nil {
		e.failures = 0
		e.next = time.Time{}
	}
}

// due returns the retryable entries whose backoff has elapsed.
func (b *backoff) due(now time.Time) []backoffEntry {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []backoffEntry
	for _, e := range b.entries {
		if e.failures > 0 && !e.inflight && !now.Before(e.next) {
			out = append(out, *e)
		}
	}
	return out
}

// forget removes key entirely.
func (b *backoff) forget(key string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.entries, key)
}
