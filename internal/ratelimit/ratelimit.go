// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package ratelimit provides a per-key sliding-window rate limiter and HTTP middleware.
package ratelimit

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"kryptkeeper/internal/clientip"
)

// Limiter is a sliding-window rate limiter keyed by arbitrary strings (typically client IPs).
// It is safe for concurrent use.
type Limiter struct {
	mu        sync.Mutex
	buckets   map[string][]time.Time
	lastSweep time.Time
	limit     int
	window    time.Duration
	// ips is parsed once here, from APP_TRUSTED_PROXY_CIDRS at construction,
	// so the per-request path does no env or CIDR parsing. Changing the env
	// var therefore needs a restart, like the rest of the hub's config.
	ips *clientip.Resolver
}

// maxKeys bounds the bucket map so a source that can mint unlimited keys (one
// IPv6 /64) cannot grow it without limit. 103 B/key measured, so about 10 MB.
const maxKeys = 100_000

// New creates a Limiter that allows up to limit requests per window per key.
func New(limit int, window time.Duration) *Limiter {
	return &Limiter{
		buckets: make(map[string][]time.Time),
		limit:   limit,
		window:  window,
		ips:     clientip.FromEnv(),
	}
}

// Allow reports whether a new request from key is within the rate limit.
// It records the request if allowed.
func (l *Limiter) Allow(key string) bool {
	return l.AllowAt(key, time.Now())
}

// AllowAt is Allow with an explicit time (useful for tests).
func (l *Limiter) AllowAt(key string, now time.Time) bool {
	if l.limit <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	cutoff := now.Add(-l.window)
	existing, known := l.buckets[key]
	if !known {
		l.makeRoomLocked(now, cutoff)
	}
	pruned := existing[:0]
	for _, ts := range existing {
		if ts.After(cutoff) {
			pruned = append(pruned, ts)
		}
	}
	if len(pruned) >= l.limit {
		l.buckets[key] = pruned
		return false
	}
	l.buckets[key] = append(pruned, now)
	return true
}

// makeRoomLocked drops keys whose requests have all aged out. The sweep runs
// at most once per window, full map or not, so it is amortised O(1) per call:
// a source minting new keys against a full table must not turn every request
// into an O(maxKeys) scan under the global mutex (RC2-N-01). If the map is
// still at the cap, one arbitrary key is dropped without sweeping: bounded
// memory wins over remembering a random client's count.
func (l *Limiter) makeRoomLocked(now, cutoff time.Time) {
	if now.Sub(l.lastSweep) >= l.window {
		l.lastSweep = now
		for k, ts := range l.buckets {
			if len(ts) == 0 || !ts[len(ts)-1].After(cutoff) {
				delete(l.buckets, k)
			}
		}
	}
	if len(l.buckets) >= maxKeys {
		for k := range l.buckets {
			delete(l.buckets, k)
			break
		}
	}
}

// Middleware returns an http.Handler that rate-limits requests by client IP.
// Requests that exceed the limit receive 429 Too Many Requests with a Retry-After header.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	retryAfterSecs := strconv.Itoa(int(l.window.Seconds()))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.Allow(l.ips.ClientIP(r)) {
			w.Header().Set("Retry-After", retryAfterSecs)
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte("rate limit exceeded\n"))
			return
		}
		next.ServeHTTP(w, r)
	})
}
