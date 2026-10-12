// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newRateLimitTestAuthenticator() *Authenticator {
	return &Authenticator{rateLimitBuckets: map[string][]time.Time{}}
}

func requestFrom(remoteAddr string, headers map[string]string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	req.RemoteAddr = remoteAddr
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

// TestClientIP_NoTrustedProxyConfigured_HeadersIgnored is acceptance #1's
// characterization test: it must pass BOTH before and after the fix, since
// the fix's trusted-proxy allowlist defaults to EMPTY. With no proxy
// configured as trusted, clientIP reads only r.RemoteAddr -- exactly what
// the shipped nginx topology (docker-compose.yml, nginx.conf) presents to
// the Go service as ONE address for the whole organisation. Two requests
// carrying different X-Real-IP values but the same RemoteAddr must resolve
// to the same client identity.
func TestClientIP_NoTrustedProxyConfigured_HeadersIgnored(t *testing.T) {
	reqA := requestFrom("10.0.0.5:41000", map[string]string{"X-Real-IP": "203.0.113.10"})
	reqB := requestFrom("10.0.0.5:41000", map[string]string{"X-Real-IP": "203.0.113.99"})

	ipA := clientIP(reqA)
	ipB := clientIP(reqB)

	if ipA != ipB {
		t.Fatalf("expected shared identity with no trusted proxy configured, got %q vs %q", ipA, ipB)
	}
	if ipA != "10.0.0.5" {
		t.Fatalf("expected clientIP to fall back to RemoteAddr, got %q", ipA)
	}
}

// TestAllowRateLimit_SharedBucketAcrossDifferentOperators proves the
// practical consequence of the characterization above through the actual
// allowRateLimit mechanism every login/refresh/OIDC caller uses: three
// "different" operators, distinguished only by a spoofable X-Real-IP header
// but all sharing nginx's RemoteAddr, exhaust ONE bucket -- the org-wide
// lockout scenario described in acceptance #1. Like the test above, this
// must hold both before and after the fix under the default (no trusted
// proxy configured) setting.
func TestAllowRateLimit_SharedBucketAcrossDifferentOperators(t *testing.T) {
	auth := newRateLimitTestAuthenticator()
	now := time.Now()
	limit := 2

	headers := []string{"203.0.113.10", "203.0.113.20", "203.0.113.30"}
	for i, h := range headers[:limit] {
		req := requestFrom("10.0.0.5:41000", map[string]string{"X-Real-IP": h})
		if !auth.allowRateLimit("login:"+clientIP(req), limit, time.Minute, now) {
			t.Fatalf("request %d (X-Real-IP=%s) within the shared limit was rejected", i, h)
		}
	}

	overReq := requestFrom("10.0.0.5:41000", map[string]string{"X-Real-IP": headers[limit]})
	if auth.allowRateLimit("login:"+clientIP(overReq), limit, time.Minute, now) {
		t.Fatal("expected a third distinct-header caller to be throttled by the shared org-wide bucket")
	}
}

// TestClientIP_TrustedProxyHonoursXRealIP is acceptance #2's positive case:
// once the peer (r.RemoteAddr) matches a configured trusted-proxy CIDR --
// the shape nginx.conf's `proxy_set_header X-Real-IP $remote_addr` produces
// -- clientIP must resolve per real client rather than collapsing to the
// proxy's own address, so per-client rate limiting actually works once an
// operator configures their proxy as trusted.
func TestClientIP_TrustedProxyHonoursXRealIP(t *testing.T) {
	t.Setenv("APP_TRUSTED_PROXY_CIDRS", "10.0.0.0/24")

	reqA := requestFrom("10.0.0.5:41000", map[string]string{"X-Real-IP": "203.0.113.10"})
	reqB := requestFrom("10.0.0.5:41000", map[string]string{"X-Real-IP": "203.0.113.99"})

	ipA := clientIP(reqA)
	ipB := clientIP(reqB)

	if ipA == ipB {
		t.Fatalf("expected distinct client identities behind a trusted proxy, got %q for both", ipA)
	}
	if ipA != "203.0.113.10" || ipB != "203.0.113.99" {
		t.Fatalf("expected clientIP to honour X-Real-IP, got %q and %q", ipA, ipB)
	}
}

// TestClientIP_UntrustedPeerCannotSpoofXRealIP is acceptance #2's negative
// case: a caller reaching the service directly (bypassing nginx, so its own
// address is the peer) is NOT in the trusted-proxy set, so a self-supplied
// X-Real-IP MUST be ignored -- honouring it would let a direct attacker mint
// a fresh bucket key per request and defeat every IP-keyed limit outright,
// strictly worse than today's shared bucket. A trusted-proxy CIDR IS
// configured here (for a different, unrelated subnet), proving this is a
// peer-address check and not just "no config means ignore headers".
func TestClientIP_UntrustedPeerCannotSpoofXRealIP(t *testing.T) {
	t.Setenv("APP_TRUSTED_PROXY_CIDRS", "10.0.0.0/24") // trusts the nginx subnet, not the attacker

	attacker1 := requestFrom("198.51.100.7:50000", map[string]string{"X-Real-IP": "1.1.1.1"})
	attacker2 := requestFrom("198.51.100.7:50000", map[string]string{"X-Real-IP": "2.2.2.2"})

	ip1 := clientIP(attacker1)
	ip2 := clientIP(attacker2)

	if ip1 != ip2 {
		t.Fatalf("untrusted peer's spoofed X-Real-IP was honoured: %q vs %q", ip1, ip2)
	}
	if ip1 != "198.51.100.7" {
		t.Fatalf("expected clientIP to fall back to the untrusted peer's own address, got %q", ip1)
	}
}

// TestClientIP_DefaultTrustedProxySetIsEmpty proves the zero-value /
// unset-env default is "trust nobody" (acceptance #2: "default EMPTY"),
// with no t.Setenv at all -- an operator who has never heard of
// APP_TRUSTED_PROXY_CIDRS is not silently downgraded to header trust.
func TestClientIP_DefaultTrustedProxySetIsEmpty(t *testing.T) {
	req := requestFrom("10.0.0.5:41000", map[string]string{"X-Real-IP": "203.0.113.10"})
	if got := clientIP(req); got != "10.0.0.5" {
		t.Fatalf("expected default-empty trusted proxy set to ignore X-Real-IP, got %q", got)
	}
}

// TestAllowRateLimit_ExpiredBucketsAreEvicted is acceptance #3: distinct
// attacker-controlled keys (unlimited under IPv6) must not accumulate in
// rateLimitBuckets forever once their window has fully expired.
// allowRateLimit sweeps only rateLimitSweepBudget entries per write, on
// EVERY write unconditionally (a full-map sweep would let a live flood of
// distinct keys turn every subsequent request into an O(map size) scan
// under rateLimitMu -- see the const doc), so eviction is gradual: expired
// keys drain out across many writes, not a single one. This test seeds a
// large number of now-expired keys, then issues enough further writes for
// the bounded sweep to have examined every seeded key with overwhelming
// probability (each write samples rateLimitSweepBudget of ~seedCount keys
// at a randomized starting point; after drainWrites writes the probability
// ANY single seeded key was never sampled is astronomically small -- see
// the per-write math below) and asserts the map has actually converged to
// just the fresh caller, not merely shrunk.
func TestAllowRateLimit_ExpiredBucketsAreEvicted(t *testing.T) {
	auth := newRateLimitTestAuthenticator()
	base := time.Now()

	const seedCount = 1025
	for i := 0; i < seedCount; i++ {
		key := fmt.Sprintf("login:203.0.113.%d-%d", i%256, i)
		if !auth.allowRateLimit(key, 5, time.Minute, base) {
			t.Fatalf("seed request %d unexpectedly throttled", i)
		}
	}
	if got := len(auth.rateLimitBuckets); got != seedCount {
		t.Fatalf("setup did not seed the expected number of keys: got %d, want %d", got, seedCount)
	}

	// Per drain write, the sweep samples rateLimitSweepBudget (128) of the
	// ~seedCount (1025) keys still present, so a single still-unswept seed
	// key survives one write with probability ~(1 - 128/1025) =~ 0.875.
	// After drainWrites=300 writes: 0.875^300 =~ 4e-18 -- with 1025 seeded
	// keys, the expected number of survivors is ~4e-15, far below any
	// realistic flake budget.
	const drainWrites = 300
	for i := 0; i < drainWrites; i++ {
		// Each drain write uses a timestamp far enough past the previous one
		// (well beyond the 1-minute window) that the trigger key's OWN
		// bucket never accumulates past its own limit -- this loop is
		// exercising the sweep of OTHER (seeded) keys, not testing the
		// trigger key's own throttling.
		now := base.Add(time.Duration(2+i) * 2 * time.Minute)
		if !auth.allowRateLimit("login:fresh-caller", 5, time.Minute, now) {
			t.Fatalf("fresh caller (drain write %d) was unexpectedly throttled", i)
		}
	}

	if got := len(auth.rateLimitBuckets); got != 1 {
		t.Fatalf("expired buckets were not evicted after %d sweeping writes: map still has %d entries, want 1 (only the fresh caller)", drainWrites, got)
	}
}

// TestAllowRateLimit_TrustedProxyKeysDifferentOperatorsSeparately is the
// discriminating half of acceptance #1/#5: proving clientIP RETURNS distinct
// values behind a trusted proxy is not the same as proving allowRateLimit
// actually buckets those values independently. Operator A exhausting the
// login cap must never throttle a DIFFERENT operator B sharing the same
// nginx peer -- otherwise the fix only looks correct in isolation, the same
// gap this ticket's own notes called out in an existing OIDC test
// (auth_oidc_login_test.go's TestOIDCLogin_RateLimitedPerClientIP asserts a
// cap is hit, never that a DIFFERENT IP survives it).
func TestAllowRateLimit_TrustedProxyKeysDifferentOperatorsSeparately(t *testing.T) {
	t.Setenv("APP_TRUSTED_PROXY_CIDRS", "10.0.0.0/24")
	auth := newRateLimitTestAuthenticator()
	now := time.Now()
	limit := 2

	operatorA := requestFrom("10.0.0.5:41000", map[string]string{"X-Real-IP": "203.0.113.10"})
	operatorB := requestFrom("10.0.0.5:41000", map[string]string{"X-Real-IP": "203.0.113.20"})

	for i := 0; i < limit; i++ {
		if !auth.allowRateLimit("login:"+clientIP(operatorA), limit, time.Minute, now) {
			t.Fatalf("operator A request %d within its own limit was rejected", i)
		}
	}
	if auth.allowRateLimit("login:"+clientIP(operatorA), limit, time.Minute, now) {
		t.Fatal("expected operator A to be throttled after exhausting its own limit")
	}

	if !auth.allowRateLimit("login:"+clientIP(operatorB), limit, time.Minute, now) {
		t.Fatal("operator B was throttled by operator A's exhausted bucket -- buckets are not actually per-client")
	}
}

// FB-10: bootstrap and internal/ratelimit share one resolver. A trusted proxy
// that appends to X-Forwarded-For leaves a client-chosen prefix, so the
// login bucket must be keyed by the rightmost untrusted entry.
func TestClientIP_TrustedProxyUsesRightmostUntrustedXFF(t *testing.T) {
	t.Setenv("APP_TRUSTED_PROXY_CIDRS", "10.0.0.0/24")

	req := requestFrom("10.0.0.5:41000", map[string]string{"X-Forwarded-For": "6.6.6.6, 203.0.113.9"})
	if got := clientIP(req); got != "203.0.113.9" {
		t.Fatalf("clientIP = %q, want rightmost untrusted 203.0.113.9", got)
	}
	untrusted := requestFrom("198.51.100.7:50000", map[string]string{"X-Forwarded-For": "6.6.6.6"})
	if got := clientIP(untrusted); got != "198.51.100.7" {
		t.Fatalf("untrusted peer's XFF honoured: %q", got)
	}
}
