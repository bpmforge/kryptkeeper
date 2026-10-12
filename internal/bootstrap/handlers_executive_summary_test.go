// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestComputeExecutiveSummary_AggregatesAndFlagsRisks(t *testing.T) {
	now := time.Now().UTC()
	certs := []CertificateItem{
		{FingerprintSHA256: "a", PublicKeyAlgorithm: "ML-DSA-65", PQCReadiness: "quantum_safe", RenewalMethod: "acme", ValidUntil: now.Add(60 * 24 * time.Hour).Format(time.RFC3339), Grade: "A", RiskScore: 5},
		{FingerprintSHA256: "b", PublicKeyAlgorithm: "RSA", PQCReadiness: "vulnerable", RenewalMethod: "manual", ValidUntil: now.Add(30 * 24 * time.Hour).Format(time.RFC3339), Grade: "B", RiskScore: 55},
		{FingerprintSHA256: "c", PublicKeyAlgorithm: "ECDSA", PQCReadiness: "vulnerable", RenewalMethod: "manual", ValidUntil: now.Add(-5 * 24 * time.Hour).Format(time.RFC3339), Grade: "F", RiskScore: 85},
	}
	s := computeExecutiveSummary(context.Background(), certs, nil, nil)

	if s.TotalCerts != 3 {
		t.Fatalf("total certs: got %d", s.TotalCerts)
	}
	if s.Expired != 1 {
		t.Errorf("expired: got %d", s.Expired)
	}
	if s.RiskCritical < 1 {
		t.Errorf("expected at least 1 critical risk, got %d", s.RiskCritical)
	}
	if len(s.TopRisks) == 0 {
		t.Error("expected top risks to be populated")
	}
	// Expired cert should surface as a headline risk.
	foundExpired := false
	for _, r := range s.TopRisks {
		if bytes.Contains([]byte(r), []byte("expired")) {
			foundExpired = true
		}
	}
	if !foundExpired {
		t.Errorf("expected an 'expired' risk statement, got %v", s.TopRisks)
	}
}

func TestExecutiveTopRisks_HealthyFallback(t *testing.T) {
	s := ExecutiveSummary{PQCScorePercent: 100, AutomationPercent: 100}
	risks := executiveTopRisks(s)
	if len(risks) != 1 || !bytes.Contains([]byte(risks[0]), []byte("healthy")) {
		t.Fatalf("expected healthy fallback, got %v", risks)
	}
}

func TestRenderExecutiveSummaryPDF_Valid(t *testing.T) {
	at := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	s := ExecutiveSummary{
		Org: "Acme", TotalCerts: 142, PQCScorePercent: 35, AutomationPercent: 60,
		CompliancePassPercent: 80, Compliance: ComplianceSummary{Pass: 8, Warn: 1, Fail: 1},
		Expired: 1, Expiring47d: 4, RiskCritical: 1, RiskHigh: 3,
		TopRisks: []string{"1 certificate(s) have already expired and need immediate renewal."},
	}
	b, err := renderExecutiveSummaryPDF(s, at)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !bytes.HasPrefix(b, []byte("%PDF-")) || !bytes.Contains(b, []byte("%%EOF")) {
		t.Fatal("not a valid PDF")
	}
	if len(b) < 500 {
		t.Fatalf("executive PDF suspiciously small: %d bytes", len(b))
	}
}

// TestComputeExecutiveSummary_FindingFunnelSuppressesUntilExpiry is the
// W2-12 acceptance-3 regression for the executive summary surface: an
// active accepted-risk exception moves the summary's Findings.Effective
// count (raw stays put, suppressed reflects the match), and the count
// returns to raw once the exception expires — proven through the real
// FindingExceptionStore's ListActive, matching
// TestCryptoPostureReport_FindingFunnelSuppressesUntilExpiry's shape.
func TestComputeExecutiveSummary_FindingFunnelSuppressesUntilExpiry(t *testing.T) {
	t.Setenv("APP_FINDINGS_DB_DSN", "file:"+t.TempDir()+"/exec-summary-funnel-expiry.db?cache=shared&_fk=1&_journal_mode=WAL")
	store, err := newFindingExceptionStoreFromEnv()
	if err != nil {
		t.Fatalf("newFindingExceptionStoreFromEnv: %v", err)
	}

	expiresAt := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	exc := FindingException{
		ID: "exc-exec-funnel", TargetType: FindingExceptionTargetCertificate, TargetID: "fp-weak",
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
	s := computeExecutiveSummary(context.Background(), certs, nil, beforeExpiry)
	if s.Findings.Raw != 2 {
		t.Fatalf("expected raw to stay 2, got %d", s.Findings.Raw)
	}
	if s.Findings.Suppressed != 1 {
		t.Fatalf("expected 1 suppressed finding before expiry, got %d", s.Findings.Suppressed)
	}
	if s.Findings.Effective != 1 {
		t.Fatalf("expected effective 1 before expiry, got %d", s.Findings.Effective)
	}

	afterExpiry, err := store.ListActive(context.Background(), expiresAt.Add(time.Minute))
	if err != nil {
		t.Fatalf("ListActive after expiry: %v", err)
	}
	s = computeExecutiveSummary(context.Background(), certs, nil, afterExpiry)
	if s.Findings.Suppressed != 0 {
		t.Fatalf("expected 0 suppressed findings after expiry (auto-reopened), got %d", s.Findings.Suppressed)
	}
	if s.Findings.Effective != 2 {
		t.Fatalf("expected effective back to raw(2) after expiry, got %d", s.Findings.Effective)
	}
}

func TestExecutiveSummaryHandler_JSONAndPDF(t *testing.T) {
	auth := newReportsTestAuth(t)
	mux := http.NewServeMux()
	registerExecutiveSummaryHandler(mux, auth, &reportCertProvider{items: buildTestCerts()}, &reportCAProvider{}, nil, stubAuditProvider{})

	// JSON tile.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/executive-summary", nil)
	req.Header.Set("Authorization", "Bearer reports-test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("json: expected 200, got %d", rec.Code)
	}

	// PDF.
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/reports/executive-summary?format=pdf", nil)
	req2.Header.Set("Authorization", "Bearer reports-test-token")
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("pdf: expected 200, got %d", rec2.Code)
	}
	if rec2.Header().Get("Content-Type") != "application/pdf" {
		t.Errorf("expected application/pdf, got %s", rec2.Header().Get("Content-Type"))
	}
	if b := rec2.Body.Bytes(); len(b) < 100 || string(b[:5]) != "%PDF-" {
		t.Error("pdf response is not a PDF")
	}
}
