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

// W12-03: scheduled anomaly detection — real-event derivation, latched
// paging, empty-estate silence, and the report surface.

func churnItems(now time.Time) []CertificateItem {
	// 5 issuances of the same subject within 24h → subject_churn.
	var items []CertificateItem
	for i := 0; i < 5; i++ {
		items = append(items, CertificateItem{
			FingerprintSHA256: string(rune('a' + i)),
			CommonName:        "churny.example.com",
			CAID:              "ca-1",
			TeamID:            "team-web",
			ValidFrom:         now.Add(-time.Duration(i) * time.Hour).Format(time.RFC3339),
			ValidUntil:        now.Add(30 * 24 * time.Hour).Format(time.RFC3339),
		})
	}
	return items
}

func TestAnomalyTickDetectsAndServes(t *testing.T) {
	now := time.Now()
	ch := &sloFakeChannel{}
	s := &AnomalyScheduler{
		certProvider: &reportCertProvider{items: churnItems(now)},
		detector:     NewAnomalyDetector(),
		channel:      ch,
		target:       "ops@example.com",
		pollInterval: time.Minute,
		seen:         map[string]bool{},
		stop:         make(chan struct{}),
	}
	s.tick(context.Background(), now)

	// Finding is served on the report surface.
	auth := newReportsTestAuth(t)
	mux := http.NewServeMux()
	registerAnomalyHandlers(mux, auth, s)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/reports/anomalies", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var resp struct {
		Data struct {
			Findings []AnomalyFinding `json:"findings"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// 5-in-24h churn data also trips volume_spike (5 >= min sample,
	// 0.2/day trailing average) — both findings served.
	kinds := map[string]bool{}
	for _, f := range resp.Data.Findings {
		kinds[f.Kind] = true
	}
	if len(resp.Data.Findings) != 2 || !kinds["subject_churn"] || !kinds["volume_spike"] {
		t.Fatalf("expected churn + spike served: %+v", resp.Data.Findings)
	}

	// Both NEW findings paged, once each.
	if len(ch.events) != 2 || ch.events[0].Priority != "high" {
		t.Fatalf("new findings must page once each: %v", ch.events)
	}
	// Steady findings: no re-page on the next tick.
	s.tick(context.Background(), now)
	if len(ch.events) != 2 {
		t.Fatalf("steady findings must not re-page: %v", ch.events)
	}
	// Cleared then re-appearing: pages again.
	s.certProvider = &reportCertProvider{items: nil}
	s.tick(context.Background(), now)
	s.certProvider = &reportCertProvider{items: churnItems(now)}
	s.tick(context.Background(), now)
	if len(ch.events) != 4 {
		t.Fatalf("re-appearing findings must page again: %v", ch.events)
	}
}

func TestAnomalyTickEmptyEstateIsSilent(t *testing.T) {
	ch := &sloFakeChannel{}
	s := &AnomalyScheduler{
		certProvider: &reportCertProvider{items: nil},
		detector:     NewAnomalyDetector(),
		channel:      ch,
		pollInterval: time.Minute,
		seen:         map[string]bool{},
		stop:         make(chan struct{}),
	}
	s.tick(context.Background(), time.Now())
	findings, _ := s.Snapshot()
	if len(findings) != 0 || len(ch.events) != 0 {
		t.Fatalf("empty estate must be silent: %v %v", findings, ch.events)
	}
}

func TestAnomalyAuthRequired(t *testing.T) {
	auth := newReportsTestAuth(t)
	mux := http.NewServeMux()
	registerAnomalyHandlers(mux, auth, NewAnomalySchedulerFromEnv(&reportCertProvider{}, nil, ""))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/reports/anomalies", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}
