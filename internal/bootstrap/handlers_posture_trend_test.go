// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPostureTrendHandler_ReturnsSnapshots(t *testing.T) {
	auth := newReportsTestAuth(t)
	store := newTestPostureStore(t)
	ctx := context.Background()
	d1 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	d2 := time.Date(2026, 6, 2, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	_ = store.Save(ctx, snapshotFromReport("psn-1", d1, sampleReport(10, 40, 50)))
	_ = store.Save(ctx, snapshotFromReport("psn-2", d2, sampleReport(12, 55, 60)))

	mux := http.NewServeMux()
	registerPostureTrendHandler(mux, auth, store, stubAuditProvider{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/crypto-posture/trend?since=2026-01-01T00:00:00Z", nil)
	req.Header.Set("Authorization", "Bearer reports-test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data PostureTrendResponse `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Data.Snapshots) != 2 {
		t.Fatalf("expected 2 snapshots, got %d", len(resp.Data.Snapshots))
	}
	if resp.Data.Snapshots[1].PQCScorePercent != 55 {
		t.Fatalf("unexpected snapshot data: %+v", resp.Data.Snapshots[1])
	}
}

func TestPostureTrendHandler_RequiresAuth(t *testing.T) {
	auth := newReportsTestAuth(t)
	store := newTestPostureStore(t)
	mux := http.NewServeMux()
	registerPostureTrendHandler(mux, auth, store, stubAuditProvider{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/crypto-posture/trend", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestPostureTrendHandler_NilStoreEmptySeries(t *testing.T) {
	auth := newReportsTestAuth(t)
	mux := http.NewServeMux()
	registerPostureTrendHandler(mux, auth, nil, stubAuditProvider{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/crypto-posture/trend", nil)
	req.Header.Set("Authorization", "Bearer reports-test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with nil store, got %d", rec.Code)
	}
}
