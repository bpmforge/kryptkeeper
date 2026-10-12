// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func redeemWorkloadToken(mux *http.ServeMux, token string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"join_token": token})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/spiffe/workload-svid", bytes.NewReader(body)))
	return rec
}

func TestSPIFFEPrivateKeyResponsesAreNoStore(t *testing.T) {
	mux, _ := workloadTestSetup(t)

	body, _ := json.Marshal(map[string]string{"spiffe_id": "spiffe://example.org/ns/prod/sa/checkout"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/spiffe/svid", body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("svid = %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("/spiffe/svid Cache-Control = %q, want no-store", rec.Header().Get("Cache-Control"))
	}

	token := registerWorkloadEntry(t, mux, "spiffe://example.org/ns/prod/sa/worker")
	rec = redeemWorkloadToken(mux, token)
	if rec.Code != http.StatusCreated {
		t.Fatalf("workload-svid = %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Pragma") != "no-cache" {
		t.Errorf("/spiffe/workload-svid cache headers = %q / %q, want no-store / no-cache", rec.Header().Get("Cache-Control"), rec.Header().Get("Pragma"))
	}
}

func TestWorkloadSVID_RateLimited(t *testing.T) {
	t.Setenv("API_RATE_LIMIT_SPIFFE_SVID_PER_MIN", "3")
	mux, _ := workloadTestSetup(t)

	for i := 0; i < 3; i++ {
		if rec := redeemWorkloadToken(mux, "guess-"+strings.Repeat("a", i)); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d, want 401 (unknown token)", i, rec.Code)
		}
	}
	if rec := redeemWorkloadToken(mux, "guess-over"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt over the limit = %d, want 429", rec.Code)
	}
}

func TestWorkloadSVID_IssuanceFailureLeaksNoEngineText(t *testing.T) {
	mux, _ := workloadTestSetup(t)
	token := registerWorkloadEntry(t, mux, "spiffe://example.org/ns/prod/sa/broken")
	t.Setenv("SPIFFE_SIGNING_CA_ID", "ca-engine-internal-id-xyz")

	rec := redeemWorkloadToken(mux, token)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when the signing CA is unusable, got %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, leak := range []string{"ca-engine-internal-id-xyz", "issuance failed:", "csr", "not found"} {
		if strings.Contains(strings.ToLower(body), strings.ToLower(leak)) {
			t.Errorf("error body leaks engine detail %q: %s", leak, body)
		}
	}
	if !strings.Contains(body, "svid issuance failed") {
		t.Errorf("expected the generic message, got %s", body)
	}
}
