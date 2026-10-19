// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"kryptkeeper/internal/logging"
)

const (
	defaultPendingActionsWriteLimit = 20
	defaultReportsLimit             = 60
	rateLimitWindow                 = time.Minute
)

// withAPIRateLimiting wraps mux with per-principal rate limiting on the
// proposal write path (POST /api/v1/pending-actions[/...]) and every
// /api/v1/reports/* path (D-030/R-C2): unthrottled, an authenticated agent
// or a runaway loop could flood pending-action proposals or hammer
// expensive report aggregations. Everything else passes through untouched.
//
// Registered once at the mux-build seam (server.go), not per-handler, so
// individual handler files never need to know about rate limiting.
func withAPIRateLimiting(mux http.Handler, auth *Authenticator) http.Handler {
	pendingActionsLimited := rateLimitByPrincipal(auth, "pending-actions", pendingActionsWriteLimitFromEnv(), rateLimitWindow, mux)
	reportsLimited := rateLimitByPrincipal(auth, "reports", reportsLimitFromEnv(), rateLimitWindow, mux)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case isPendingActionsWrite(r):
			pendingActionsLimited.ServeHTTP(w, r)
		case isReportsPath(r):
			reportsLimited.ServeHTTP(w, r)
		default:
			mux.ServeHTTP(w, r)
		}
	})
}

func isPendingActionsWrite(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	p := r.URL.Path
	return p == "/api/v1/pending-actions" || strings.HasPrefix(p, "/api/v1/pending-actions/")
}

func isReportsPath(r *http.Request) bool {
	p := r.URL.Path
	return p == "/api/v1/reports" || strings.HasPrefix(p, "/api/v1/reports/")
}

func pendingActionsWriteLimitFromEnv() int {
	return intFromEnvOrDefault("API_RATE_LIMIT_PENDING_ACTIONS_PER_MIN", defaultPendingActionsWriteLimit)
}

func reportsLimitFromEnv() int {
	return intFromEnvOrDefault("API_RATE_LIMIT_REPORTS_PER_MIN", defaultReportsLimit)
}

func intFromEnvOrDefault(envVar string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(envVar))
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return fallback
	}
	return n
}

// ProtocolRateLimitsFromEnv reads the ACME/EST protocol-mount limits (W22-39):
// RATELIMIT_PROTOCOL_PER_CREDENTIAL (default 600) for verified credentials and
// RATELIMIT_UNAUTH_PER_IP (default 30) for everything else, both per
// rateLimitWindow. Unset, non-integer, zero or negative falls back to the
// default: a limit of 0 would silently disable the limiter, which a typo must
// not be able to do.
func ProtocolRateLimitsFromEnv() (perCredential, unauthPerIP int) {
	return positiveIntFromEnv("RATELIMIT_PROTOCOL_PER_CREDENTIAL", 600),
		positiveIntFromEnv("RATELIMIT_UNAUTH_PER_IP", 30)
}

func positiveIntFromEnv(envVar string, fallback int) int {
	n := intFromEnvOrDefault(envVar, fallback)
	if n <= 0 {
		if strings.TrimSpace(os.Getenv(envVar)) != "" {
			logging.Warnf("%s must be a positive integer; using default %d", envVar, fallback)
		}
		return fallback
	}
	return n
}
