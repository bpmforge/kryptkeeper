// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newRateLimitTestAuth(t *testing.T) *Authenticator {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32-chars-minimum!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	return NewAuthenticatorFromEnv()
}

func stubOKHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

// TestWithAPIRateLimiting_PendingActionsWriteIsLimitedPerPrincipal is the
// D-030/R-C2/W1-05 core regression: a POST to /api/v1/pending-actions is
// rate-limited independently per authenticated principal -- one principal
// hitting the cap does not affect a different principal's budget.
func TestWithAPIRateLimiting_PendingActionsWriteIsLimitedPerPrincipal(t *testing.T) {
	auth := newRateLimitTestAuth(t)
	t.Setenv("API_RATE_LIMIT_PENDING_ACTIONS_PER_MIN", "2")
	t.Setenv("API_RATE_LIMIT_REPORTS_PER_MIN", "100")

	_, keyA, err := auth.CreateAPIKey("agent-a", "agent-a", "pki-operator", nil, "", "", time.Now())
	if err != nil {
		t.Fatalf("create key A: %v", err)
	}
	_, keyB, err := auth.CreateAPIKey("agent-b", "agent-b", "pki-operator", nil, "", "", time.Now())
	if err != nil {
		t.Fatalf("create key B: %v", err)
	}

	handler := withAPIRateLimiting(stubOKHandler(), auth)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	post := func(key string) int {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/pending-actions", nil)
		req.Header.Set("Authorization", "Bearer "+key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	if code := post(keyA); code != http.StatusOK {
		t.Fatalf("A request 1: expected 200, got %d", code)
	}
	if code := post(keyA); code != http.StatusOK {
		t.Fatalf("A request 2: expected 200, got %d", code)
	}
	if code := post(keyA); code != http.StatusTooManyRequests {
		t.Fatalf("A request 3: expected 429 (cap is 2), got %d", code)
	}

	// A completely different principal has its own, unaffected budget.
	if code := post(keyB); code != http.StatusOK {
		t.Fatalf("B request 1: expected 200 (separate principal budget), got %d", code)
	}
}

// TestWithAPIRateLimiting_PendingActionsReadIsNotLimited proves only
// "writes" (POST) are limited, matching the acceptance criterion's own
// wording -- GET (list) is unaffected even after exhausting the write cap.
func TestWithAPIRateLimiting_PendingActionsReadIsNotLimited(t *testing.T) {
	auth := newRateLimitTestAuth(t)
	t.Setenv("API_RATE_LIMIT_PENDING_ACTIONS_PER_MIN", "1")

	_, key, err := auth.CreateAPIKey("agent-c", "agent-c", "pki-operator", nil, "", "", time.Now())
	if err != nil {
		t.Fatalf("create key: %v", err)
	}

	handler := withAPIRateLimiting(stubOKHandler(), auth)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	for i := 0; i < 5; i++ {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/pending-actions", nil)
		req.Header.Set("Authorization", "Bearer "+key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET %d: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %d: expected 200 (reads are never rate-limited), got %d", i, resp.StatusCode)
		}
	}
}

// TestWithAPIRateLimiting_ReportsPathIsLimitedPerPrincipal covers the
// second half of the acceptance criterion: any method under
// /api/v1/reports/* is limited, independently from the pending-actions
// budget (different scope prefix in the shared bucket map).
func TestWithAPIRateLimiting_ReportsPathIsLimitedPerPrincipal(t *testing.T) {
	auth := newRateLimitTestAuth(t)
	t.Setenv("API_RATE_LIMIT_REPORTS_PER_MIN", "2")

	_, key, err := auth.CreateAPIKey("agent-d", "agent-d", "pki-operator", nil, "", "", time.Now())
	if err != nil {
		t.Fatalf("create key: %v", err)
	}

	handler := withAPIRateLimiting(stubOKHandler(), auth)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	get := func(path string) int {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	if code := get("/api/v1/reports/crypto-posture"); code != http.StatusOK {
		t.Fatalf("reports request 1: expected 200, got %d", code)
	}
	if code := get("/api/v1/reports/expiry-timeline"); code != http.StatusOK {
		t.Fatalf("reports request 2 (different report, same budget): expected 200, got %d", code)
	}
	if code := get("/api/v1/reports/ca-health"); code != http.StatusTooManyRequests {
		t.Fatalf("reports request 3: expected 429 (cap is 2), got %d", code)
	}
}

// TestWithAPIRateLimiting_UnauthenticatedRequestPassesThrough proves the
// middleware never masks or duplicates an auth failure -- an unauthenticated
// request reaches the wrapped handler unchanged, which is responsible for
// its own 401.
func TestWithAPIRateLimiting_UnauthenticatedRequestPassesThrough(t *testing.T) {
	auth := newRateLimitTestAuth(t)

	handler := withAPIRateLimiting(stubOKHandler(), auth)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/v1/pending-actions", "application/json", nil)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected the unauthenticated request to reach the wrapped handler (200 from the stub), got %d", resp.StatusCode)
	}
}

// TestWithAPIRateLimiting_UnrelatedPathIsNeverLimited proves paths outside
// pending-actions writes and /reports/* are never subject to this limiter,
// regardless of how many requests are sent.
func TestWithAPIRateLimiting_UnrelatedPathIsNeverLimited(t *testing.T) {
	auth := newRateLimitTestAuth(t)
	t.Setenv("API_RATE_LIMIT_PENDING_ACTIONS_PER_MIN", "1")
	t.Setenv("API_RATE_LIMIT_REPORTS_PER_MIN", "1")

	_, key, err := auth.CreateAPIKey("agent-e", "agent-e", "pki-operator", nil, "", "", time.Now())
	if err != nil {
		t.Fatalf("create key: %v", err)
	}

	handler := withAPIRateLimiting(stubOKHandler(), auth)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	for i := 0; i < 5; i++ {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/certificates", nil)
		req.Header.Set("Authorization", "Bearer "+key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET %d: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %d: expected 200 (unrelated path, never limited), got %d", i, resp.StatusCode)
		}
	}
}

// TestMetricsHandler_ServesPrometheusTextOnGet proves the standalone
// /metrics handler wired into Run() (FR-P60) serves the same Prometheus
// exposition format as the protocolMux copy in cmd/kryptkeeper/main.go, and
// rejects non-GET methods.
func TestMetricsHandler_ServesPrometheusTextOnGet(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	metricsHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain; version=0.0.4; charset=utf-8" {
		t.Fatalf("unexpected content-type: %s", ct)
	}
}

func TestMetricsHandler_RejectsNonGet(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/metrics", nil)
	metricsHandler(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}
