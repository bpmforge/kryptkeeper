// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/metrics"
)

// metricsTestChain mirrors the hub chain's metrics-relevant layers around a
// mux that serves /metrics plus the probes.
func metricsTestChain(t *testing.T, store ConfigStore) http.Handler {
	t.Helper()
	prev := metricsBearer
	metricsBearer = &metricsBearerResolver{store: store, now: time.Now}
	t.Cleanup(func() { metricsBearer = prev })
	mux := http.NewServeMux()
	registerMetaHandlers(mux, nil)
	mux.HandleFunc("/metrics", metricsHandler)
	mux.HandleFunc("/boom", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) })
	return withAccessLog(withMetricsAuth(withHTTPMetrics(mux)))
}

func chainGet(h http.Handler, path, auth string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestMetricsExposesAtLeast25Families(t *testing.T) {
	h := metricsTestChain(t, nil)
	body := chainGet(h, "/metrics", "").Body.String()
	if n := strings.Count(body, "# TYPE "); n < 25 {
		t.Fatalf("families = %d, want >= 25", n)
	}
	for _, name := range []string{"kryptkeeper_slo_breaches_total", "kryptkeeper_cert_expiry_days", "kryptkeeper_http_requests_total"} {
		if !strings.Contains(body, name) {
			t.Errorf("missing %s", name)
		}
	}
}

func TestMetricsBearerOnReturns401WithoutToken(t *testing.T) {
	const tok = "scrape-token-Zx81"
	t.Setenv(metricsBearerEnv, tok)
	h := metricsTestChain(t, nil)

	var logs bytes.Buffer
	prevLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prevLogger) })

	if r := chainGet(h, "/metrics", ""); r.Code != http.StatusUnauthorized || r.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("no token: %d", r.Code)
	}
	if r := chainGet(h, "/metrics", "Bearer wrong"); r.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: %d", r.Code)
	}
	if r := chainGet(h, "/metrics", "Bearer "+tok); r.Code != http.StatusOK {
		t.Fatalf("right token: %d", r.Code)
	}
	for _, p := range []string{"/healthz", "/readyz"} {
		if r := chainGet(h, p, ""); r.Code != http.StatusOK {
			t.Fatalf("%s must stay unauthenticated: %d", p, r.Code)
		}
	}
	if strings.Contains(logs.String(), tok) || strings.Contains(strings.ToLower(logs.String()), "authorization") {
		t.Fatalf("bearer or Authorization header leaked into logs: %s", logs.String())
	}
}

func TestMetricsBearerFromConfigStoreAndAudited(t *testing.T) {
	const tok = "store-token-Qw42"
	store := newConfigTestStore(t)
	mux2, _, rec2 := newRecordingConfigMuxWithStore(t, store)

	put := doConfigRequest(mux2, http.MethodPut, "/api/v1/config/metrics.bearer_token", "test-token", `{"value":"`+tok+`"}`)
	if put.Code != http.StatusNoContent {
		t.Fatalf("PUT = %d %s", put.Code, put.Body.String())
	}
	if !rec2.has("config.set", AuditOutcomeSuccess) || !rec2.has("config.metrics_auth.update", AuditOutcomeSuccess) {
		t.Fatalf("expected config.set and config.metrics_auth.update: %+v", rec2.entries)
	}
	dump, _ := json.Marshal(rec2.entries)
	if strings.Contains(put.Body.String(), tok) || strings.Contains(string(dump), tok) {
		t.Fatal("token leaked into response or audit rows")
	}
	list := doConfigRequest(mux2, http.MethodGet, "/api/v1/config", "test-token", "")
	if strings.Contains(list.Body.String(), tok) {
		t.Fatal("GET /config returned the token")
	}
	var resp configListResponse
	if err := json.Unmarshal(list.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	s, ok := findSetting(resp.Data, "metrics.bearer_token")
	if !ok || !s.Secret || !s.Configured || s.Value != "" {
		t.Fatalf("setting = %+v ok=%v", s, ok)
	}

	h := metricsTestChain(t, store)
	if r := chainGet(h, "/metrics", ""); r.Code != http.StatusUnauthorized {
		t.Fatalf("store-backed bearer not enforced: %d", r.Code)
	}
	if r := chainGet(h, "/metrics", "Bearer "+tok); r.Code != http.StatusOK {
		t.Fatalf("store-backed bearer rejected: %d", r.Code)
	}
}

func TestMetricsAuthKeyChangeAudited(t *testing.T) {
	mux, _, rec := newRecordingConfigMux(t)
	const tok = "audit-token-Lm90"
	if r := doConfigRequest(mux, http.MethodPut, "/api/v1/config/metrics.bearer_token", "test-token", `{"value":"`+tok+`"}`); r.Code != http.StatusNoContent {
		t.Fatalf("PUT = %d", r.Code)
	}
	if !rec.has("config.set", AuditOutcomeSuccess) || !rec.has("config.metrics_auth.update", AuditOutcomeSuccess) {
		t.Fatalf("missing audit rows: %+v", rec.entries)
	}
	dump, _ := json.Marshal(rec.entries)
	if strings.Contains(string(dump), tok) {
		t.Fatal("audit rows contain the token")
	}
	if r := doConfigRequest(mux, http.MethodDelete, "/api/v1/config/metrics.bearer_token", "test-token", ""); r.Code != http.StatusNoContent {
		t.Fatalf("DELETE = %d", r.Code)
	}
	if !rec.has("config.metrics_auth.update", AuditOutcomeSuccess) {
		t.Fatal("reset not audited")
	}
}

func TestMetricsBearerResolverCachesWithinTTL(t *testing.T) {
	t.Setenv(metricsBearerEnv, "one")
	now := time.Unix(1000, 0)
	m := &metricsBearerResolver{now: func() time.Time { return now }}
	if got := m.resolve(t.Context()); got != "one" {
		t.Fatal(got)
	}
	t.Setenv(metricsBearerEnv, "two")
	if got := m.resolve(t.Context()); got != "one" {
		t.Fatalf("cache bypassed: %s", got)
	}
	now = now.Add(metricsBearerTTL + time.Second)
	if got := m.resolve(t.Context()); got != "two" {
		t.Fatalf("cache not expired: %s", got)
	}
}

func TestHTTPMetricsCounted(t *testing.T) {
	h := metricsTestChain(t, nil)
	reqs, e5, e4 := metrics.HTTPRequests.Load(), metrics.HTTPResponses5xx.Load(), metrics.HTTPResponses4xx.Load()
	chainGet(h, "/healthz", "")
	if got := metrics.HTTPRequests.Load() - reqs; got != 1 {
		t.Fatalf("requests delta = %d", got)
	}
	chainGet(h, "/boom", "")
	if got := metrics.HTTPResponses5xx.Load() - e5; got != 1 {
		t.Fatalf("5xx delta = %d", got)
	}
	req := httptest.NewRequest(http.MethodPost, "/healthz", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)
	if metrics.HTTPResponses4xx.Load()-e4 < 1 {
		t.Fatal("4xx not counted")
	}
}
