// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"net/http"
	"time"

	"kryptkeeper/internal/clientip"
)

// rateLimitByPrincipal wraps next with a per-authenticated-principal rate
// limit (D-030/R-C2/FR-R9): an agent or a runaway loop could otherwise flood
// pending-action proposals or hammer expensive report aggregations with no
// limit at all. Reuses the same allowRateLimit bucket mechanism already
// used for login/refresh, scoped by a prefix so distinct call sites (e.g.
// "pending-actions" vs "reports") never share the same principal's bucket.
//
// A request that fails authentication is passed through to next unchanged
// -- this middleware only ever adds a 429 on top of a request that would
// otherwise succeed; it never masks or duplicates the wrapped handler's own
// 401, which is authoritative.
func rateLimitByPrincipal(auth *Authenticator, scope string, limit int, window time.Duration, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()
		pd, err := auth.AuthenticatePrincipalDetails(r, now)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}
		if !auth.allowRateLimit(scope+":"+pd.ID, limit, window, now) {
			writeTooManyRequests(w, "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// rateLimitSweepBudget bounds how many OTHER keys a single write examines
// for expiry, beyond its own key (handled unconditionally above). Every
// login:, refresh:, oidc-login:, and oidc-callback: key embeds clientIP, and
// IPv6 alone gives an attacker unlimited distinct values to mint; an
// attacker who never revisits a key would otherwise leave that key's bucket
// sitting in the map forever, since nothing else ever touches that key
// again.
//
// A first draft swept the ENTIRE map, but only once len(rateLimitBuckets)
// crossed a size threshold. Measured against a map of 5000 keys that are
// all still live (a sustained flood of distinct keys within one window --
// exactly the attack this ticket names), that full sweep found nothing to
// delete and still cost ~470x a call against an empty map, every one of
// them serialized under rateLimitMu, the same mutex that gates login,
// refresh, both OIDC endpoints, and every per-principal limit -- trading
// unbounded memory for unbounded per-request CPU on the mutex guarding
// login is not a fix. Worse, the threshold gate meant that once a sweep
// shrank the map back under the threshold, sweeping STOPPED even though
// hundreds of fully-expired entries could still remain, since nothing
// forces the count back up again until new growth re-crosses the
// threshold -- a map that looks "small enough" while still quietly
// retaining expired keys indefinitely, which is exactly what acceptance #3
// forbids.
//
// This version runs a bounded sweep on EVERY write, unconditionally: each
// write examines at most rateLimitSweepBudget entries (chosen empirically;
// see auth_rate_limit_test.go's TestAllowRateLimit_ExpiredBucketsAreEvicted
// for the coverage math), so cost is O(budget) regardless of map size --
// cheap on the common small map (examining "up to budget" entries of a
// 20-key map just examines all 20), and bounded even under a live flood of
// thousands. Go's map iteration starts at a randomized bucket on each
// range, so repeated writes examine different, effectively random subsets,
// and expired keys drain out continuously across writes rather than
// requiring a size trigger. This does not promise the map never exceeds
// budget-many-times-many-writes under a sustained flood of genuinely live
// keys (that population is bounded by attack rate times window, not by
// anything this function controls) -- it promises keys whose window has
// FULLY EXPIRED do not survive indefinitely, unconditionally on map size.
// A hard reject-when-full cap (the oidcLoginStateStore.put shape) was
// deliberately not used here: rejecting a login-throttle check either lets
// the request through unchecked (a bypass) or denies a legitimate
// operator's login (a cross-user DoS) -- unlike a rejected SSO login,
// which is simply retryable.
const rateLimitSweepBudget = 128

func (a *Authenticator) allowRateLimit(key string, limit int, window time.Duration, now time.Time) bool {
	if limit <= 0 {
		return true
	}
	a.rateLimitMu.Lock()
	defer a.rateLimitMu.Unlock()

	cutoff := now.Add(-window)

	existing := a.rateLimitBuckets[key]
	pruned := existing[:0]
	for _, ts := range existing {
		if ts.After(cutoff) {
			pruned = append(pruned, ts)
		}
	}
	allowed := len(pruned) < limit
	if allowed {
		pruned = append(pruned, now)
	}
	a.rateLimitBuckets[key] = pruned

	// Sweeping every OTHER key in the map with THIS call's window as the
	// cutoff is only correct because every allowRateLimit caller in this
	// codebase passes window=time.Minute today (handlers_auth.go's login and
	// refresh limits, auth_oidc_login.go's SSO pair, ratelimit_mw.go's
	// per-principal limits) -- rateLimitBuckets stores raw insertion
	// timestamps, not a per-key window, and its type is fixed by the
	// Authenticator struct in auth.go, out of this ticket's write_scope to
	// change. If a future caller ever passes a window SHORTER than another
	// live key's own window, this sweep would evict that other key's still
	// -valid entries early -- an early bypass of THAT key's limit, not a
	// mere leniency. Keep every allowRateLimit window equal, or give
	// rateLimitBuckets a real per-key expiry before relying on this.
	examined := 0
	for k, v := range a.rateLimitBuckets {
		if examined >= rateLimitSweepBudget {
			break
		}
		examined++
		survivors := v[:0]
		for _, ts := range v {
			if ts.After(cutoff) {
				survivors = append(survivors, ts)
			}
		}
		if len(survivors) == 0 {
			delete(a.rateLimitBuckets, k)
		} else {
			a.rateLimitBuckets[k] = survivors
		}
	}

	return allowed
}

// clientIP identifies the caller an IP-keyed rate limit should bucket by. The
// derivation (trusted-proxy peer check, rightmost-untrusted X-Forwarded-For,
// X-Real-IP fallback) lives in internal/clientip so the protocol-endpoint
// limiters in internal/ratelimit cannot disagree with it.
//
// APP_TRUSTED_PROXY_CIDRS is parsed per call because this is a free function
// reached from handlers that hold no Authenticator config to inject a
// Resolver from; the list is a few CIDRs and the parse is trivial next to the
// bucket work under rateLimitMu. Default EMPTY: no header is trusted.
func clientIP(r *http.Request) string {
	return clientip.FromEnv().ClientIP(r)
}
