// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPQCDeadlines_DaysRemaining(t *testing.T) {
	now := time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC)
	ds := pqcDeadlines(now)
	if len(ds) != 3 {
		t.Fatalf("expected 3 deadlines, got %d", len(ds))
	}
	// CNSA 2.0 software signing is 2030-01-01 → ~365 days from 2029-01-01.
	if ds[0].DaysRemaining < 360 || ds[0].DaysRemaining > 370 {
		t.Errorf("unexpected days remaining: %d", ds[0].DaysRemaining)
	}
	if ds[0].Passed {
		t.Error("2030 deadline should not be passed in 2029")
	}
}

func TestPQCStatus(t *testing.T) {
	if pqcStatus(0, 0, 10) != "complete" {
		t.Error("0 vulnerable, 0 leaf-only should be complete")
	}
	if pqcStatus(5, 0, 85) != "on_track" {
		t.Error("85% should be on_track")
	}
	if pqcStatus(5, 0, 50) != "at_risk" {
		t.Error("50% should be at_risk")
	}
	if pqcStatus(5, 0, 20) != "behind" {
		t.Error("20% should be behind")
	}
}

// TestPQCStatus_LeafOnlyBlocksComplete proves G-70/D-104's headline fix: a
// fleet with zero fully-vulnerable certs but some quantum_safe_leaf_only
// certs (the exact state migrate-wave produces re-issuing against existing
// classical CAs) must NOT report "complete" -- their chains remain
// classically forgeable, and D-104 was resolved specifically to prevent
// that being reported as done. PQCScorePercent still gives credit (tested
// separately in TestComputeCryptoPosture_AggregatesLeafOnlyCategory); only
// the strongest claim ("complete") is withheld.
func TestPQCStatus_LeafOnlyBlocksComplete(t *testing.T) {
	if got := pqcStatus(0, 3, 100); got == "complete" {
		t.Errorf("pqcStatus(vulnerable=0, leafOnly=3, score=100) = %q, must not be complete while leaf-only certs remain", got)
	}
	if got := pqcStatus(0, 3, 100); got != "on_track" {
		t.Errorf("pqcStatus(vulnerable=0, leafOnly=3, score=100) = %q, want on_track (score-based, since complete is withheld)", got)
	}
}

func TestComputePQCCountdown_TrendFromSnapshots(t *testing.T) {
	now := time.Now().UTC()
	certs := buildTestCerts()
	snaps := []PostureSnapshot{
		{CapturedAt: "2026-06-01T00:00:00Z", PQCScorePercent: 20},
		{CapturedAt: "2026-06-10T00:00:00Z", PQCScorePercent: 35},
	}
	rep := computePQCCountdown(context.Background(), certs, snaps, nil, now, nil)
	if rep.TotalCerts != len(certs) {
		t.Errorf("total certs: got %d", rep.TotalCerts)
	}
	if len(rep.Trend) != 2 || rep.Trend[1].PQCScorePercent != 35 {
		t.Errorf("trend not carried: %+v", rep.Trend)
	}
	if rep.Status == "" {
		t.Error("status should be set")
	}
}

// TestComputePQCCountdown_FindingFunnelSuppressesUntilExpiry is the W2-12
// acceptance-3 regression for the PQC countdown surface: an active
// accepted-risk exception moves the countdown's Findings.Effective count
// (raw stays put, suppressed reflects the match), and the count returns to
// raw once the exception expires — proven through the real
// FindingExceptionStore's ListActive, matching
// TestCryptoPostureReport_FindingFunnelSuppressesUntilExpiry's shape.
func TestComputePQCCountdown_FindingFunnelSuppressesUntilExpiry(t *testing.T) {
	t.Setenv("APP_FINDINGS_DB_DSN", "file:"+t.TempDir()+"/pqc-countdown-funnel-expiry.db?cache=shared&_fk=1&_journal_mode=WAL")
	store, err := newFindingExceptionStoreFromEnv()
	if err != nil {
		t.Fatalf("newFindingExceptionStoreFromEnv: %v", err)
	}

	expiresAt := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	exc := FindingException{
		ID: "exc-pqc-funnel", TargetType: FindingExceptionTargetCertificate, TargetID: "fp-weak",
		FindingCode: "WEAK_RSA_KEY", JustificationCode: JustificationRiskAccepted,
		CreatedBy: "alice", CreatedAt: expiresAt.Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt: expiresAt.Format(time.RFC3339),
	}
	if err := store.Create(context.Background(), exc); err != nil {
		t.Fatalf("create exception: %v", err)
	}

	certs := findingFunnelTestCerts()

	beforeExpiry, err := store.ListActive(context.Background(), expiresAt.Add(-time.Minute))
	if err != nil {
		t.Fatalf("ListActive before expiry: %v", err)
	}
	rep := computePQCCountdown(context.Background(), certs, nil, nil, expiresAt.Add(-time.Minute), beforeExpiry)
	if rep.Findings.Raw != 2 {
		t.Fatalf("expected raw to stay 2, got %d", rep.Findings.Raw)
	}
	if rep.Findings.Suppressed != 1 {
		t.Fatalf("expected 1 suppressed finding before expiry, got %d", rep.Findings.Suppressed)
	}
	if rep.Findings.Effective != 1 {
		t.Fatalf("expected effective 1 before expiry, got %d", rep.Findings.Effective)
	}

	afterExpiry, err := store.ListActive(context.Background(), expiresAt.Add(time.Minute))
	if err != nil {
		t.Fatalf("ListActive after expiry: %v", err)
	}
	rep = computePQCCountdown(context.Background(), certs, nil, nil, expiresAt.Add(time.Minute), afterExpiry)
	if rep.Findings.Suppressed != 0 {
		t.Fatalf("expected 0 suppressed findings after expiry (auto-reopened), got %d", rep.Findings.Suppressed)
	}
	if rep.Findings.Effective != 2 {
		t.Fatalf("expected effective back to raw(2) after expiry, got %d", rep.Findings.Effective)
	}
}

func TestRenderPQCCountdownPDF_Valid(t *testing.T) {
	at := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	rep := PQCCountdownReport{
		Org: "Acme", TotalCerts: 10, Vulnerable: 4, MigrationReady: 2, QuantumSafe: 4,
		PQCScorePercent: 60, Status: "at_risk", Deadlines: pqcDeadlines(at),
		Waves: []WaveProgress{{MigrationWave: MigrationWave{Name: "Internal"}, Total: 4, Migrated: 1, ProgressPercent: 25}},
		Trend: []PQCTrendPoint{{CapturedAt: "2026-06-01T00:00:00Z", PQCScorePercent: 40}, {CapturedAt: "2026-06-18T00:00:00Z", PQCScorePercent: 60}},
	}
	b, err := renderPQCCountdownPDF(rep, at)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !bytes.HasPrefix(b, []byte("%PDF-")) || !bytes.Contains(b, []byte("%%EOF")) {
		t.Fatal("not a valid PDF")
	}
}

func TestPQCCountdownHandler_JSONAndPDF(t *testing.T) {
	auth := newReportsTestAuth(t)
	certs := &reportCertProvider{items: buildTestCerts()}
	mux := http.NewServeMux()
	registerPQCCountdownHandler(mux, auth, certs, nil, nil, nil, stubAuditProvider{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/pqc-countdown", nil)
	req.Header.Set("Authorization", "Bearer reports-test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("json: expected 200, got %d", rec.Code)
	}
	var resp struct {
		Data PQCCountdownReport `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Data.Deadlines) != 3 {
		t.Errorf("expected 3 deadlines in payload")
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/reports/pqc-countdown?format=pdf", nil)
	req2.Header.Set("Authorization", "Bearer reports-test-token")
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK || rec2.Header().Get("Content-Type") != "application/pdf" {
		t.Fatalf("pdf: got %d / %s", rec2.Code, rec2.Header().Get("Content-Type"))
	}
}
