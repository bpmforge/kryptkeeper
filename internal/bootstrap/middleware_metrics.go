// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/metrics"
)

const (
	metricsBearerKey = "metrics.bearer_token"
	metricsBearerEnv = "KRYPTKEEPER_METRICS_BEARER_TOKEN"
	metricsBearerTTL = 10 * time.Second
)

// withHTTPMetrics counts every request the hub serves. It sits inside
// withMetricsAuth so scrapes rejected with 401 are not counted as traffic,
// and outside rate limiting so 429s are.
func withHTTPMetrics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		metrics.HTTPRequests.Inc()
		metrics.HTTPRequestDuration.Observe(time.Since(start).Seconds())
		switch {
		case rec.status >= 500:
			metrics.HTTPResponses5xx.Inc()
			if rec.status == http.StatusServiceUnavailable && r.URL.Path == "/readyz" {
				metrics.ReadyzFailures.Inc()
			}
		case rec.status >= 400:
			metrics.HTTPResponses4xx.Inc()
		}
	})
}

// withMetricsAuth guards /metrics with the optional bearer. Probes and every
// other path pass through untouched. It deliberately never logs the header.
func withMetricsAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/metrics" {
			if tok := metricsBearer.resolve(r.Context()); tok != "" && !metrics.BearerMatches(r.Header.Get("Authorization"), tok) {
				w.Header().Set("WWW-Authenticate", "Bearer")
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// metricsBearerResolver reads the bearer from the config store (Secret key)
// with the env var as fallback, cached for metricsBearerTTL so a scrape does
// not hit the database every time. The cache is TTL-only: a changed token
// takes effect within one TTL.
type metricsBearerResolver struct {
	mu       sync.Mutex
	store    ConfigStore
	factory  func() ConfigStore
	cached   string
	cachedAt time.Time
	now      func() time.Time
}

var metricsBearer = &metricsBearerResolver{factory: newConfigStoreFromEnv, now: time.Now}

func (m *metricsBearerResolver) resolve(ctx context.Context) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.cachedAt.IsZero() && m.now().Sub(m.cachedAt) < metricsBearerTTL {
		return m.cached
	}
	m.cached = m.lookup(ctx)
	m.cachedAt = m.now()
	return m.cached
}

func (m *metricsBearerResolver) lookup(ctx context.Context) string {
	if m.store == nil && m.factory != nil {
		m.store = m.factory()
	}
	if m.store != nil {
		cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		// Secret rows keep value NULL (HasValue is false), so Resolve is the
		// only presence check; not-found is the normal "use env" path.
		b, err := m.store.Resolve(cctx, metricsBearerKey)
		switch {
		case err == nil:
			return strings.TrimSpace(string(b))
		case !errors.Is(err, errConfigOverrideNotFound):
			slog.Warn("metrics bearer lookup failed; using env fallback")
		}
	}
	return strings.TrimSpace(os.Getenv(metricsBearerEnv))
}
