// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLimiter_AllowsWithinLimit(t *testing.T) {
	l := New(3, time.Minute)
	now := time.Now()
	for i := 0; i < 3; i++ {
		if !l.AllowAt("ip1", now) {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
}

func TestLimiter_BlocksOverLimit(t *testing.T) {
	l := New(3, time.Minute)
	now := time.Now()
	for i := 0; i < 3; i++ {
		l.AllowAt("ip1", now)
	}
	if l.AllowAt("ip1", now) {
		t.Fatal("4th request should be blocked")
	}
}

func TestLimiter_SlidingWindowResetsAfterWindow(t *testing.T) {
	l := New(3, time.Minute)
	now := time.Now()
	for i := 0; i < 3; i++ {
		l.AllowAt("ip1", now)
	}
	// Advance past the window — old requests should be pruned.
	future := now.Add(61 * time.Second)
	if !l.AllowAt("ip1", future) {
		t.Fatal("request after window expiry should be allowed")
	}
}

func TestLimiter_IndependentKeysDoNotInterfere(t *testing.T) {
	l := New(2, time.Minute)
	now := time.Now()
	l.AllowAt("a", now)
	l.AllowAt("a", now)
	// "a" is now at limit; "b" should still be allowed.
	if !l.AllowAt("b", now) {
		t.Fatal("key b should be independent of key a")
	}
	// "a" is blocked.
	if l.AllowAt("a", now) {
		t.Fatal("key a should be blocked")
	}
}

func TestLimiter_ZeroLimitAllowsAll(t *testing.T) {
	l := New(0, time.Minute)
	for i := 0; i < 1000; i++ {
		if !l.Allow("any") {
			t.Fatal("zero-limit should allow all requests")
		}
	}
}

func TestMiddleware_Returns429WhenExceeded(t *testing.T) {
	l := New(2, time.Minute)
	handler := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "10.0.0.1:1234"

	for i := 0; i < 2; i++ {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i+1, rr.Code)
		}
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rr.Code)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header on 429")
	}
}

// requestFrom builds a request carrying a specific peer address and headers,
// mirroring internal/bootstrap's auth_rate_limit_test.go helper of the same
// shape -- RemoteAddr is set explicitly rather than left at
// httptest.NewRequest's default (192.0.2.1), which would hide any bucket
// collapse across the two requests a test compares.
func requestFrom(remoteAddr string, headers map[string]string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/acme/", nil)
	req.RemoteAddr = remoteAddr
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

// TestMiddleware_DefaultTrustedProxySetIsEmpty_SpoofedXFFSharesOneBucket is
// the FIXED counterpart of the characterization this ticket's earlier commit
// added (git log: "test(W6-12): characterize ratelimit clientIP's
// unconditional X-Forwarded-For trust"). That commit proved the pre-fix bug
// by asserting each spoofed X-Forwarded-For value got its OWN 2-request
// allowance against the same RemoteAddr; re-running that exact scenario
// against the fixed clientIP was RED (the second "attacker" was rejected as
// 429 instead of getting a fresh bucket) before this test replaced it --
// recorded in the fix commit body per PLAYBOOK. With APP_TRUSTED_PROXY_CIDRS
// unset (default empty), all three spoofed identities must now collapse to
// ONE shared bucket keyed by the peer address, so only `limit` requests
// total succeed across all of them.
func TestMiddleware_DefaultTrustedProxySetIsEmpty_SpoofedXFFSharesOneBucket(t *testing.T) {
	limit := 2
	l := New(limit, time.Minute)
	handler := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	attackers := []string{"203.0.113.10", "203.0.113.20", "203.0.113.30"}
	allowed := 0
	for _, xff := range attackers {
		req := requestFrom("198.51.100.7:50000", map[string]string{"X-Forwarded-For": xff})
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code == http.StatusOK {
			allowed++
		} else if rr.Code != http.StatusTooManyRequests {
			t.Fatalf("X-Forwarded-For=%s: unexpected status %d", xff, rr.Code)
		}
	}
	if allowed != limit {
		t.Fatalf("expected exactly %d requests allowed across all spoofed X-Forwarded-For values (one shared bucket), got %d", limit, allowed)
	}
}

// TestClientIP_DefaultTrustedProxySetIsEmpty proves the zero-value / unset-env
// default is "trust nobody", with no t.Setenv at all -- an operator who has
// never heard of APP_TRUSTED_PROXY_CIDRS is not silently downgraded to header
// trust.
func TestClientIP_DefaultTrustedProxySetIsEmpty(t *testing.T) {
	req := requestFrom("10.0.0.5:41000", map[string]string{"X-Forwarded-For": "203.0.113.10"})
	if got := New(1, time.Minute).ips.ClientIP(req); got != "10.0.0.5" {
		t.Fatalf("expected default-empty trusted proxy set to ignore X-Forwarded-For, got %q", got)
	}
}

// TestClientIP_TrustedProxyHonoursXForwardedFor is the positive case: once
// the peer (r.RemoteAddr) matches a configured trusted-proxy CIDR, clientIP
// must resolve per real client rather than collapsing to the proxy's own
// address.
func TestClientIP_TrustedProxyHonoursXForwardedFor(t *testing.T) {
	t.Setenv("APP_TRUSTED_PROXY_CIDRS", "10.0.0.0/24")

	reqA := requestFrom("10.0.0.5:41000", map[string]string{"X-Forwarded-For": "203.0.113.10"})
	reqB := requestFrom("10.0.0.5:41000", map[string]string{"X-Forwarded-For": "203.0.113.99"})

	ipA := New(1, time.Minute).ips.ClientIP(reqA)
	ipB := New(1, time.Minute).ips.ClientIP(reqB)

	if ipA == ipB {
		t.Fatalf("expected distinct client identities behind a trusted proxy, got %q for both", ipA)
	}
	if ipA != "203.0.113.10" || ipB != "203.0.113.99" {
		t.Fatalf("expected clientIP to honour X-Forwarded-For, got %q and %q", ipA, ipB)
	}
}

// TestClientIP_UntrustedPeerCannotSpoofXForwardedFor is the negative case: a
// caller reaching the service directly (its own address is the peer, not in
// the trusted set) must NOT have its self-supplied X-Forwarded-For honoured
// -- honouring it would let a direct attacker mint a fresh bucket per
// request. A trusted-proxy CIDR IS configured here (a different, unrelated
// subnet), proving this is a peer-address check and not just "no config
// means ignore headers".
func TestClientIP_UntrustedPeerCannotSpoofXForwardedFor(t *testing.T) {
	t.Setenv("APP_TRUSTED_PROXY_CIDRS", "10.0.0.0/24") // trusts an unrelated subnet, not the attacker

	attacker1 := requestFrom("198.51.100.7:50000", map[string]string{"X-Forwarded-For": "1.1.1.1"})
	attacker2 := requestFrom("198.51.100.7:50000", map[string]string{"X-Forwarded-For": "2.2.2.2"})

	ip1 := New(1, time.Minute).ips.ClientIP(attacker1)
	ip2 := New(1, time.Minute).ips.ClientIP(attacker2)

	if ip1 != ip2 {
		t.Fatalf("untrusted peer's spoofed X-Forwarded-For was honoured: %q vs %q", ip1, ip2)
	}
	if ip1 != "198.51.100.7" {
		t.Fatalf("expected clientIP to fall back to the untrusted peer's own address, got %q", ip1)
	}
}

// TestMiddleware_TrustedProxyBucketsDifferentClientsSeparately is the
// discriminating half of acceptance #2: proving clientIP RETURNS distinct
// values behind a trusted proxy is not the same as proving the Limiter
// actually buckets those values independently. Client A exhausting its limit
// must never throttle a DIFFERENT client B sharing the same trusted peer.
func TestMiddleware_TrustedProxyBucketsDifferentClientsSeparately(t *testing.T) {
	t.Setenv("APP_TRUSTED_PROXY_CIDRS", "10.0.0.0/24")

	limit := 2
	l := New(limit, time.Minute)
	handler := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	clientA := requestFrom("10.0.0.5:41000", map[string]string{"X-Forwarded-For": "203.0.113.10"})
	clientB := requestFrom("10.0.0.5:41000", map[string]string{"X-Forwarded-For": "203.0.113.20"})

	for i := 0; i < limit; i++ {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, clientA)
		if rr.Code != http.StatusOK {
			t.Fatalf("client A request %d within its own limit: expected 200, got %d", i+1, rr.Code)
		}
	}
	overRec := httptest.NewRecorder()
	handler.ServeHTTP(overRec, clientA)
	if overRec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected client A to be throttled after exhausting its own limit, got %d", overRec.Code)
	}

	bRec := httptest.NewRecorder()
	handler.ServeHTTP(bRec, clientB)
	if bRec.Code != http.StatusOK {
		t.Fatalf("client B was throttled by client A's exhausted bucket -- buckets are not actually per-client (got %d)", bRec.Code)
	}
}

func TestMiddleware_PassthroughWhenUnderLimit(t *testing.T) {
	l := New(100, time.Minute)
	called := 0
	handler := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		w.WriteHeader(http.StatusNoContent)
	}))

	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "192.168.1.1:9999"
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("request %d: expected 204, got %d", i+1, rr.Code)
		}
	}
	if called != 10 {
		t.Fatalf("expected 10 calls to inner handler, got %d", called)
	}
}

// FB-10: a trusted proxy that APPENDS to X-Forwarded-For leaves the
// client-supplied prefix intact, so the leftmost entry is attacker-chosen.
// The rightmost untrusted entry is the one the proxy itself recorded.
func TestMiddleware_TrustedProxyIgnoresSpoofedLeftmostXFF(t *testing.T) {
	t.Setenv("APP_TRUSTED_PROXY_CIDRS", "10.0.0.0/24")

	limit := 2
	l := New(limit, time.Minute)
	handler := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	allowed := 0
	for _, spoof := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
		req := requestFrom("10.0.0.5:41000", map[string]string{"X-Forwarded-For": spoof + ", 203.0.113.9"})
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code == http.StatusOK {
			allowed++
		}
	}
	if allowed != limit {
		t.Fatalf("one real client behind the proxy must share one bucket regardless of spoofed prefix: allowed %d, want %d", allowed, limit)
	}
	if got := l.ips.ClientIP(requestFrom("10.0.0.5:41000", map[string]string{"X-Forwarded-For": "6.6.6.6, 203.0.113.9"})); got != "203.0.113.9" {
		t.Fatalf("ClientIP = %q, want rightmost untrusted 203.0.113.9", got)
	}
}
