// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/keyinventory"
	"kryptkeeper/internal/sshkeys"
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

// W24-35: key PQC readiness in the executive summary.

func withKeyPQCFixtures(t *testing.T, extra ...keyinventory.KeySource) {
	t.Helper()
	srcs := append([]keyinventory.KeySource{
		fakeKeySource{provider: "aws-kms", keys: []keyinventory.Key{
			{Provider: "aws-kms", KeyID: "q", PQCReadiness: "quantum_safe"},
			{Provider: "aws-kms", KeyID: "v", PQCReadiness: "vulnerable"},
			{Provider: "aws-kms", KeyID: "e", PQCReadiness: ""},
		}},
		fakeKeySource{provider: "azure-kv", keys: []keyinventory.Key{
			{Provider: "azure-kv", KeyID: "v2", PQCReadiness: "vulnerable"},
			{Provider: "azure-kv", KeyID: "u", PQCReadiness: "unknown"},
		}},
	}, extra...)
	withKeySources(t, srcs...)
	inv := sshkeys.NewInventory()
	inv.Add(sshkeys.SSHKey{Fingerprint: "SHA256:x", KeyType: sshkeys.RSA, BitSize: 3072, Host: "h"})
	withSSHUserInventory(t, inv)
	prev := keyInventoryDiscovery
	keyInventoryDiscovery = nil
	t.Cleanup(func() { keyInventoryDiscovery = prev })
}

func TestSummarizeKeyPQC_CountsAllClasses(t *testing.T) {
	withKeyPQCFixtures(t)
	s := summarizeKeyPQC(collectKeyInventory(context.Background()))
	if s.Ready != 1 || s.NotReady != 3 || s.Unknown != 2 || s.Total != 6 || s.Ready+s.NotReady+s.Unknown != s.Total {
		t.Fatalf("unexpected %+v", s)
	}
}

func execSummaryKeyPQC(t *testing.T) (int, map[string]any) {
	t.Helper()
	mux := http.NewServeMux()
	registerExecutiveSummaryHandler(mux, newReportsTestAuth(t), &reportCertProvider{items: buildTestCerts()}, &reportCAProvider{}, nil, stubAuditProvider{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/executive-summary", nil)
	req.Header.Set("Authorization", "Bearer reports-test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var body struct {
		Data struct {
			KeyPQC map[string]any `json:"key_pqc"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return rec.Code, body.Data.KeyPQC
}

func TestExecutiveSummaryHandler_IncludesKeyPQC(t *testing.T) {
	withKeyPQCFixtures(t, fakeKeySource{provider: "gcp-kms", err: errors.New("boom arn:aws:secret")})
	code, k := execSummaryKeyPQC(t)
	if code != http.StatusOK || k == nil {
		t.Fatalf("code=%d key_pqc=%v", code, k)
	}
	if k["ready"] != float64(1) || k["not_ready"] != float64(3) || k["unknown"] != float64(2) || k["total"] != float64(6) {
		t.Fatalf("counts: %v", k)
	}
	errs, _ := k["errors"].([]any)
	if len(errs) != 1 || errs[0] != "cloud key inventory unavailable: gcp-kms" {
		t.Fatalf("errors: %v", k["errors"])
	}
}

func TestExecutiveSummaryHandler_NoKeySourcesIsZeroNotAbsent(t *testing.T) {
	withKeySources(t)
	withSSHUserInventory(t, sshkeys.NewInventory())
	prev := keyInventoryDiscovery
	keyInventoryDiscovery = nil
	t.Cleanup(func() { keyInventoryDiscovery = prev })
	_, k := execSummaryKeyPQC(t)
	if k == nil || k["total"] != float64(0) || k["ready"] != float64(0) {
		t.Fatalf("expected zeroed key_pqc, got %v", k)
	}
}

func TestExecutiveSummaryHandler_KeyPQCHiddenFromTenantScoped(t *testing.T) {
	mux, acmeToken, _ := setupTenantWritePathTest(t)
	withKeyPQCFixtures(t)
	keyPQC := func(token, tenant string) (int, bool) {
		var rec *httptest.ResponseRecorder
		if tenant != "" {
			rec = doTenantReq(mux, http.MethodGet, "/api/v1/reports/executive-summary", token, tenant)
		} else {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/executive-summary", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			rec = httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
		}
		var body struct {
			Data map[string]json.RawMessage `json:"data"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		_, ok := body.Data["key_pqc"]
		return rec.Code, ok
	}
	if code, ok := keyPQC("root-token", ""); code != http.StatusOK || !ok {
		t.Fatalf("super-admin: code=%d has key_pqc=%v", code, ok)
	}
	if code, ok := keyPQC(acmeToken, "acme"); code != http.StatusOK || ok {
		t.Fatalf("tenant-scoped: code=%d has key_pqc=%v (must be omitted)", code, ok)
	}
}

func execSummaryGET(t *testing.T, mux *http.ServeMux, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer reports-test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: %d %s", path, rec.Code, rec.Body.String())
	}
	return rec
}

func TestExecutiveSummaryHandler_TrendMatchesPostureTrendEndpoint(t *testing.T) {
	auth := newReportsTestAuth(t)
	store := newTestPostureStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for i, days := range []int{120, 40, 10} {
		at := now.AddDate(0, 0, -days).Format(time.RFC3339)
		if err := store.Save(ctx, snapshotFromReport("psn-"+string(rune('a'+i)), at, sampleReport(10+i, 40, 50))); err != nil {
			t.Fatal(err)
		}
	}
	mux := http.NewServeMux()
	registerExecutiveSummaryHandlerWithTrend(mux, auth, &reportCertProvider{items: buildTestCerts()}, &reportCAProvider{}, nil, store, stubAuditProvider{})
	registerPostureTrendHandler(mux, auth, store, stubAuditProvider{})

	var sum struct {
		Data struct {
			Trend ExecutiveTrend `json:"trend"`
		} `json:"data"`
	}
	if err := json.Unmarshal(execSummaryGET(t, mux, "/api/v1/reports/executive-summary").Body.Bytes(), &sum); err != nil {
		t.Fatal(err)
	}
	var tr struct {
		Data PostureTrendResponse `json:"data"`
	}
	since := now.AddDate(0, 0, -90).Format(time.RFC3339)
	if err := json.Unmarshal(execSummaryGET(t, mux, "/api/v1/reports/crypto-posture/trend?since="+since).Body.Bytes(), &tr); err != nil {
		t.Fatal(err)
	}
	if sum.Data.Trend.Days != 90 || len(sum.Data.Trend.Points) != 2 || len(tr.Data.Snapshots) != 2 {
		t.Fatalf("points=%d snapshots=%d days=%d, want 2/2/90", len(sum.Data.Trend.Points), len(tr.Data.Snapshots), sum.Data.Trend.Days)
	}
	for i, p := range sum.Data.Trend.Points {
		sn := tr.Data.Snapshots[i]
		if p.CapturedAt != sn.CapturedAt || p.TotalCerts != sn.TotalCerts || !reflect.DeepEqual(p.Grades, sn.Report.GradeDistribution) {
			t.Fatalf("point %d %+v != snapshot %+v", i, p, sn)
		}
	}
}

func TestExecutiveSummaryPDF_ContainsTrendSection(t *testing.T) {
	prev := pdfCompression
	pdfCompression = false
	t.Cleanup(func() { pdfCompression = prev })
	auth := newReportsTestAuth(t)
	store := newTestPostureStore(t)
	at := time.Now().UTC().AddDate(0, 0, -5)
	if err := store.Save(context.Background(), snapshotFromReport("psn-pdf", at.Format(time.RFC3339), sampleReport(7, 40, 50))); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerExecutiveSummaryHandlerWithTrend(mux, auth, &reportCertProvider{items: buildTestCerts()}, &reportCAProvider{}, nil, store, stubAuditProvider{})
	text := pdfText(execSummaryGET(t, mux, "/api/v1/reports/executive-summary?format=pdf").Body.Bytes())
	for _, want := range []string{"Posture trend (last 90 days)", at.Format("2006-01-02")} {
		if !strings.Contains(text, want) {
			t.Errorf("PDF missing %q", want)
		}
	}
}

func TestExecutiveSummaryPDF_EmptyTrendIsExplicit(t *testing.T) {
	prev := pdfCompression
	pdfCompression = false
	t.Cleanup(func() { pdfCompression = prev })
	mux := http.NewServeMux()
	registerExecutiveSummaryHandlerWithTrend(mux, newReportsTestAuth(t), &reportCertProvider{}, &reportCAProvider{}, nil, newTestPostureStore(t), stubAuditProvider{})
	var sum struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(execSummaryGET(t, mux, "/api/v1/reports/executive-summary").Body.Bytes(), &sum); err != nil {
		t.Fatal(err)
	}
	var tr struct {
		Points json.RawMessage `json:"points"`
	}
	if err := json.Unmarshal(sum.Data["trend"], &tr); err != nil || string(tr.Points) != "[]" {
		t.Fatalf("trend.points = %s err=%v, want []", tr.Points, err)
	}
	text := pdfText(execSummaryGET(t, mux, "/api/v1/reports/executive-summary?format=pdf").Body.Bytes())
	if !strings.Contains(text, "No posture snapshots in the last 90 days.") {
		t.Error("PDF missing explicit empty state")
	}
}

func TestExecutiveSummary_TrendHiddenFromTenantScoped(t *testing.T) {
	mux, acmeToken, _ := setupTenantWritePathTest(t)
	hasTrend := func(token, tenant string) (int, bool) {
		var rec *httptest.ResponseRecorder
		if tenant != "" {
			rec = doTenantReq(mux, http.MethodGet, "/api/v1/reports/executive-summary", token, tenant)
		} else {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/executive-summary", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			rec = httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
		}
		var body struct {
			Data map[string]json.RawMessage `json:"data"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		_, ok := body.Data["trend"]
		return rec.Code, ok
	}
	if code, ok := hasTrend("root-token", ""); code != http.StatusOK || !ok {
		t.Fatalf("super-admin: code=%d has trend=%v", code, ok)
	}
	if code, ok := hasTrend(acmeToken, "acme"); code != http.StatusOK || ok {
		t.Fatalf("tenant-scoped: code=%d has trend=%v (must be omitted)", code, ok)
	}
}

// W24-49: the PDF prints the same key counts as the JSON (the PQC posture
// page's key inventory), and omits the line when they are not provided.
func TestExecutiveSummaryPDF_KeyReadinessLine(t *testing.T) {
	prev := pdfCompression
	pdfCompression = false
	t.Cleanup(func() { pdfCompression = prev })
	withKeyPQCFixtures(t)
	at := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)

	s := computeExecutiveSummary(context.Background(), buildTestCerts(), nil, nil)
	ks := summarizeKeyPQC(collectKeyInventory(context.Background()))
	s.KeyPQC = &ks
	b, err := renderExecutiveSummaryPDF(s, at)
	if err != nil {
		t.Fatal(err)
	}
	if want := "Keys ready / not ready / unknown for PQC migration: 1 / 3 / 2"; !strings.Contains(pdfText(b), want) {
		t.Errorf("PDF lacks %q", want)
	}

	s.KeyPQC = nil
	b, err = renderExecutiveSummaryPDF(s, at)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(pdfText(b), "Keys ready") {
		t.Error("tenant-scoped summary must not print key counts")
	}
}
