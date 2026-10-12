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
