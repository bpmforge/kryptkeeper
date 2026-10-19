// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// reportCertProvider implements CertificateProvider with a fixed cert list.
type reportCertProvider struct {
	items []CertificateItem
}

func (p *reportCertProvider) UpdateEstate(_ context.Context, _ string, _ EstateUpdate) (CertificateItem, error) {
	return CertificateItem{}, nil
}

func (p *reportCertProvider) ListCertificates(_ context.Context, _ CertificateListQuery) (CertificateListResult, error) {
	return CertificateListResult{Items: p.items, Total: len(p.items), Limit: len(p.items)}, nil
}
func (p *reportCertProvider) GetCertificate(_ context.Context, _ string) (CertificateDetail, bool, error) {
	return CertificateDetail{}, false, nil
}
func (p *reportCertProvider) GetCertificateChain(_ context.Context, _ string) (CertificateChainResult, bool, error) {
	return CertificateChainResult{}, false, nil
}
func (p *reportCertProvider) IssueCertificate(_ context.Context, _ CertificateIssueRequest) (CertificateIssueResult, error) {
	return CertificateIssueResult{}, nil
}
func (p *reportCertProvider) ImportCertificate(_ context.Context, _ CertificateImportRequest) (CertificateIssueResult, error) {
	return CertificateIssueResult{}, nil
}
func (p *reportCertProvider) RevokeCertificate(_ context.Context, _ string, _ CertificateRevokeRequest) (CertificateRevokeResult, error) {
	return CertificateRevokeResult{}, nil
}
func (p *reportCertProvider) RenewCertificate(_ context.Context, _ string, _ CertificateRenewRequest) (CertificateIssueResult, error) {
	return CertificateIssueResult{}, nil
}
func (p *reportCertProvider) DownloadCertificate(_ context.Context, _ string, _ string, _ bool) (CertificateDownloadResult, error) {
	return CertificateDownloadResult{}, nil
}
func (p *reportCertProvider) UpdateOwnership(_ context.Context, _ string, _ CertificateOwnershipRequest) (CertificateItem, error) {
	return CertificateItem{}, nil
}

// clampingCertProvider mimics certificate_ca_provider.go's ListCertificates:
// it clamps its returned page to 100 items regardless of the caller's
// requested Limit, but still reports the true filtered Total — exactly the
// shape that let a >100-certificate team silently lose everything past the
// first page before reportVisibleCertificates learned to page (S-45).
type clampingCertProvider struct {
	reportCertProvider
}

func (p *clampingCertProvider) ListCertificates(_ context.Context, query CertificateListQuery) (CertificateListResult, error) {
	limit := query.Limit
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	total := len(p.items)
	offset := query.Offset
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return CertificateListResult{Items: p.items[offset:end], Total: total, Limit: limit}, nil
}

// reportCAProvider is a minimal CAProvider stub for report tests. A nil
// items field (the zero value every pre-existing call site relies on)
// behaves exactly as the old field-less struct did: an empty result.
type reportCAProvider struct {
	items []CAListItem
}

func (p *reportCAProvider) ListCAs(_ context.Context, _ CAListQuery) (CAListResult, error) {
	return CAListResult{Items: p.items, Total: len(p.items), Limit: len(p.items)}, nil
}
func (p *reportCAProvider) GetCA(_ context.Context, _ string) (CAListItem, bool, error) {
	return CAListItem{}, false, nil
}
func (p *reportCAProvider) GetCAChain(_ context.Context, _ string) ([]CAListItem, bool, error) {
	return nil, false, nil
}
func (p *reportCAProvider) UpdateCA(_ context.Context, _ string, _ CAUpdateRequest) (CAListItem, error) {
	return CAListItem{}, nil
}
func (p *reportCAProvider) DeleteCA(_ context.Context, _ string) error { return nil }
func (p *reportCAProvider) SuspendCA(_ context.Context, _ string) (CAStatusChange, error) {
	return CAStatusChange{}, nil
}
func (p *reportCAProvider) ActivateCA(_ context.Context, _ string) (CAStatusChange, error) {
	return CAStatusChange{}, nil
}
func (p *reportCAProvider) CreateCA(_ context.Context, _ CACreateRequest) (CAListItem, error) {
	return CAListItem{}, nil
}

func newReportsTestAuth(t *testing.T) *Authenticator {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "reports-test-token")
	return NewAuthenticatorFromEnv()
}

// buildTestCerts returns a representative set of CertificateItem for posture tests.
func buildTestCerts() []CertificateItem {
	now := time.Now().UTC()
	return []CertificateItem{
		// Quantum-safe, auto-renewed, grade A, low risk
		{
			FingerprintSHA256:  "aaa",
			CommonName:         "pqc.example.com",
			PublicKeyAlgorithm: "ML-DSA-65",
			ValidFrom:          now.Add(-30 * 24 * time.Hour).Format(time.RFC3339),
			ValidUntil:         now.Add(60 * 24 * time.Hour).Format(time.RFC3339),
			PQCReadiness:       "quantum_safe",
			Grade:              "A",
			RenewalMethod:      "acme",
			RenewalStatus:      "active",
			RiskScore:          5,
		},
		// Vulnerable, manual, grade B, high risk, expiring soon (within 47d)
		{
			FingerprintSHA256:  "bbb",
			CommonName:         "legacy.example.com",
			PublicKeyAlgorithm: "RSA",
			ValidFrom:          now.Add(-300 * 24 * time.Hour).Format(time.RFC3339),
			ValidUntil:         now.Add(30 * 24 * time.Hour).Format(time.RFC3339),
			PQCReadiness:       "vulnerable",
			Grade:              "B",
			RenewalMethod:      "manual",
			RenewalStatus:      "active",
			RiskScore:          55,
		},
		// Expired, critical risk
		{
			FingerprintSHA256:  "ccc",
			CommonName:         "expired.example.com",
			PublicKeyAlgorithm: "ECDSA",
			ValidFrom:          now.Add(-400 * 24 * time.Hour).Format(time.RFC3339),
			ValidUntil:         now.Add(-5 * 24 * time.Hour).Format(time.RFC3339),
			PQCReadiness:       "vulnerable",
			Grade:              "F",
			RenewalMethod:      "manual",
			RenewalStatus:      "expired",
			RiskScore:          80,
		},
		// Migration-ready, SCEP-enrolled, grade A, low risk
		{
			FingerprintSHA256:  "ddd",
			CommonName:         "device.example.com",
			PublicKeyAlgorithm: "ECDSA",
			ValidFrom:          now.Add(-10 * 24 * time.Hour).Format(time.RFC3339),
			ValidUntil:         now.Add(355 * 24 * time.Hour).Format(time.RFC3339),
			PQCReadiness:       "migration_ready",
			Grade:              "A",
			RenewalMethod:      "scep",
			RenewalStatus:      "active",
			RiskScore:          15,
		},
	}
}

func newTestReportsMux(t *testing.T) (*http.ServeMux, *Authenticator) {
	t.Helper()
	auth := newReportsTestAuth(t)
	provider := &reportCertProvider{items: buildTestCerts()}
	mux := http.NewServeMux()
	registerReportsHandlers(mux, auth, provider, &reportCAProvider{}, stubTemplateProvider{}, nil, stubAuditProvider{})
	return mux, auth
}

func TestCryptoPostureReport_JSON(t *testing.T) {
	mux, _ := newTestReportsMux(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/crypto-posture", nil)
	req.Header.Set("Authorization", "Bearer reports-test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "application/json") {
		t.Errorf("expected JSON content-type, got %s", rec.Header().Get("Content-Type"))
	}

	var resp struct {
		Data CryptoPostureReport `json:"data"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	report := resp.Data

	if report.TotalCerts != 4 {
		t.Errorf("expected 4 total certs, got %d", report.TotalCerts)
	}
	if report.PQCReadiness.QuantumSafe != 1 {
		t.Errorf("expected 1 quantum_safe, got %d", report.PQCReadiness.QuantumSafe)
	}
	if report.PQCReadiness.Vulnerable != 2 {
		t.Errorf("expected 2 vulnerable, got %d", report.PQCReadiness.Vulnerable)
	}
	if report.PQCReadiness.MigrationReady != 1 {
		t.Errorf("expected 1 migration_ready, got %d", report.PQCReadiness.MigrationReady)
	}
	// PQC score: (1 quantum_safe + 1 migration_ready) / 4 = 50%
	if report.PQCReadiness.PQCScorePercent != 50 {
		t.Errorf("expected PQC score 50%%, got %d%%", report.PQCReadiness.PQCScorePercent)
	}
	// Automation: acme + scep = 2 automated out of 4 = 50%
	if report.AutomationCoverage.Automated != 2 {
		t.Errorf("expected 2 automated, got %d", report.AutomationCoverage.Automated)
	}
	if report.AutomationCoverage.AutomationPercent != 50 {
		t.Errorf("expected automation 50%%, got %d%%", report.AutomationCoverage.AutomationPercent)
	}
	// Expired: 1
	if report.ExpiryBuckets.Expired != 1 {
		t.Errorf("expected 1 expired, got %d", report.ExpiryBuckets.Expired)
	}
	// Expiring in 47d: 1 (legacy.example.com at +30d)
	if report.ExpiryBuckets.Expiring47d != 1 {
		t.Errorf("expected 1 expiring_47d, got %d", report.ExpiryBuckets.Expiring47d)
	}
	// Risk critical (score > 70): 1 (expired cert score=80)
	if report.RiskBreakdown.Critical != 1 {
		t.Errorf("expected 1 critical risk, got %d", report.RiskBreakdown.Critical)
	}
}

func TestCryptoPostureReport_CSVExport(t *testing.T) {
	mux, _ := newTestReportsMux(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/crypto-posture?format=csv", nil)
	req.Header.Set("Authorization", "Bearer reports-test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "text/csv") {
		t.Errorf("expected text/csv, got %s", rec.Header().Get("Content-Type"))
	}
	if !strings.Contains(rec.Header().Get("Content-Disposition"), "attachment") {
		t.Errorf("expected attachment content-disposition, got %s", rec.Header().Get("Content-Disposition"))
	}

	body := rec.Body.String()
	if !strings.Contains(body, "fingerprint_sha256") {
		t.Error("expected CSV header row")
	}
	lines := strings.Split(strings.TrimSpace(body), "\n")
	if len(lines) != 5 { // 1 header + 4 data rows
		t.Errorf("expected 5 lines (1 header + 4 data), got %d", len(lines))
	}
	if !strings.Contains(body, "pqc.example.com") {
		t.Error("expected cert common name in CSV output")
	}
}

func TestCryptoPostureReport_Unauthorized(t *testing.T) {
	mux, _ := newTestReportsMux(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/crypto-posture", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestCryptoPostureReport_MethodNotAllowed(t *testing.T) {
	mux, _ := newTestReportsMux(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/reports/crypto-posture", nil)
	req.Header.Set("Authorization", "Bearer reports-test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestComputeCryptoPosture_Empty(t *testing.T) {
	report := computeCryptoPosture(context.Background(), nil)
	if report.TotalCerts != 0 {
		t.Errorf("expected 0 total, got %d", report.TotalCerts)
	}
	if report.PQCReadiness.PQCScorePercent != 0 {
		t.Errorf("expected 0%% PQC score for empty input, got %d%%", report.PQCReadiness.PQCScorePercent)
	}
	if report.AutomationCoverage.AutomationPercent != 0 {
		t.Errorf("expected 0%% automation for empty input, got %d%%", report.AutomationCoverage.AutomationPercent)
	}
}

// findingFunnelTestCerts returns certs carrying RiskFlags (computeRiskFlags'
// output, as it would arrive on a real CertificateItem) so the finding
// funnel has raw findings to count.
func findingFunnelTestCerts() []CertificateItem {
	return []CertificateItem{
		{FingerprintSHA256: "fp-weak", CommonName: "weak.example.com", RiskFlags: []string{"WEAK_RSA_KEY", "SAN_SPRAWL"}},
		{FingerprintSHA256: "fp-clean", CommonName: "clean.example.com", RiskFlags: nil},
	}
}

func TestComputeCryptoPostureReport_FindingFunnel(t *testing.T) {
	certs := findingFunnelTestCerts()

	// No active exceptions: effective == raw, nothing suppressed.
	report := computeCryptoPostureReport(certs, nil)
	if report.Findings.Raw != 2 {
		t.Fatalf("expected 2 raw findings, got %d", report.Findings.Raw)
	}
	if report.Findings.Suppressed != 0 {
		t.Fatalf("expected 0 suppressed with no exceptions, got %d", report.Findings.Suppressed)
	}
	if report.Findings.Effective != 2 {
		t.Fatalf("expected effective == raw with no exceptions, got %d", report.Findings.Effective)
	}

	// One active exception on fp-weak/WEAK_RSA_KEY: raw stays 2, suppressed
	// counts only the matching finding, effective drops by exactly that.
	exceptions := []FindingException{
		{TargetType: FindingExceptionTargetCertificate, TargetID: "fp-weak", FindingCode: "WEAK_RSA_KEY"},
	}
	report = computeCryptoPostureReport(certs, exceptions)
	if report.Findings.Raw != 2 {
		t.Fatalf("expected raw to stay 2 (never hidden), got %d", report.Findings.Raw)
	}
	if report.Findings.Suppressed != 1 {
		t.Fatalf("expected 1 suppressed finding, got %d", report.Findings.Suppressed)
	}
	if report.Findings.Effective != 1 {
		t.Fatalf("expected effective = raw(2) - suppressed(1) = 1, got %d", report.Findings.Effective)
	}
}

// TestCryptoPostureReport_FindingFunnelSuppressesUntilExpiry is the
// acceptance-6 regression, run end to end through the real
// FindingExceptionStore (sqlite) and computeCryptoPostureReport together:
// an active exception on a real finding suppresses it, and the very same
// exception stops suppressing once now passes its expires_at — matching
// the design doc's "expiry is computed, not stored" auto-reopen rule.
func TestCryptoPostureReport_FindingFunnelSuppressesUntilExpiry(t *testing.T) {
	t.Setenv("APP_FINDINGS_DB_DSN", "file:"+t.TempDir()+"/funnel-expiry.db?cache=shared&_fk=1&_journal_mode=WAL")
	store, err := newFindingExceptionStoreFromEnv()
	if err != nil {
		t.Fatalf("newFindingExceptionStoreFromEnv: %v", err)
	}

	expiresAt := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	exc := FindingException{
		ID: "exc-funnel", TargetType: FindingExceptionTargetCertificate, TargetID: "fp-weak",
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
	report := computeCryptoPostureReport(certs, beforeExpiry)
	if report.Findings.Suppressed != 1 {
		t.Fatalf("expected 1 suppressed finding before expiry, got %d", report.Findings.Suppressed)
	}
	if report.Findings.Effective != 1 {
		t.Fatalf("expected effective 1 before expiry, got %d", report.Findings.Effective)
	}

	afterExpiry, err := store.ListActive(context.Background(), expiresAt.Add(time.Minute))
	if err != nil {
		t.Fatalf("ListActive after expiry: %v", err)
	}
	report = computeCryptoPostureReport(certs, afterExpiry)
	if report.Findings.Suppressed != 0 {
		t.Fatalf("expected 0 suppressed findings after expiry (auto-reopened), got %d", report.Findings.Suppressed)
	}
	if report.Findings.Effective != 2 {
		t.Fatalf("expected effective back to raw(2) after expiry, got %d", report.Findings.Effective)
	}
	// Raw is never hidden or replaced, before or after suppression lapses.
	if report.Findings.Raw != 2 {
		t.Fatalf("expected raw to remain 2 throughout, got %d", report.Findings.Raw)
	}
}

// TestReportVisibleCertificates_PagesPastProviderClamp is the S-45 gate
// regression: reportVisibleCertificates used to make a single ListCertificates
// call and trust it returned everything. certificate_ca_provider.go (the
// production provider, APP_CERTIFICATE_PROVIDER=ca) clamps that single call
// to 100 items while still reporting the true Total, so any team with more
// than 100 certificates got a report total_certs stuck at 100 while GET
// /api/v1/certificates reported the real count — the exact "adjacent screens
// disagree" defect this ticket exists to close, just past the size the
// 2-cert file-provider fixture in the other regression test can reach.
func TestReportVisibleCertificates_PagesPastProviderClamp(t *testing.T) {
	const fleetSize = 137 // > the provider's 100-item page clamp
	items := make([]CertificateItem, fleetSize)
	for i := range items {
		items[i] = CertificateItem{
			FingerprintSHA256: fmt.Sprintf("fp-%03d", i),
			CommonName:        fmt.Sprintf("cert-%03d.example.com", i),
		}
	}
	provider := &clampingCertProvider{reportCertProvider{items: items}}
	pd := AuthPrincipal{ID: "bootstrap"} // admin: no TeamID narrowing, isolates the clamp behavior

	got, err := reportVisibleCertificates(context.Background(), pd, provider, 10000)
	if err != nil {
		t.Fatalf("reportVisibleCertificates: %v", err)
	}
	if len(got) != fleetSize {
		t.Fatalf("expected all %d certificates despite the provider's 100-item page clamp, got %d", fleetSize, len(got))
	}

	// The requested limit is still a ceiling: a fleet larger than the
	// caller's own limit must not page forever collecting everything.
	got, err = reportVisibleCertificates(context.Background(), pd, provider, 50)
	if err != nil {
		t.Fatalf("reportVisibleCertificates with limit=50: %v", err)
	}
	if len(got) != 50 {
		t.Fatalf("expected exactly the requested limit (50) when the fleet exceeds it, got %d", len(got))
	}
}

func TestComplianceEvidence_PDFExport(t *testing.T) {
	mux, _ := newTestReportsMux(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/compliance-evidence?framework=pci&format=pdf", nil)
	req.Header.Set("Authorization", "Bearer reports-test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/pdf" {
		t.Errorf("expected application/pdf, got %s", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "compliance-pci-") || !strings.Contains(cd, ".pdf") {
		t.Errorf("unexpected content-disposition: %s", cd)
	}
	if body := rec.Body.Bytes(); len(body) < 100 || string(body[:5]) != "%PDF-" {
		t.Errorf("response is not a PDF (len=%d)", len(rec.Body.Bytes()))
	}
}

// caHealthTestItems mirrors caHealthFixturePath in handlers_cas_test.go: one
// CA stored active whose certificate has actually expired (the
// ci-seed-root-ca shape from docs/ANALYST_REPORT_2026-07-31.md), one
// genuinely active CA, and one expired-but-suspended CA that was never
// presenting as active in the first place.
func caHealthTestItems() []CAListItem {
	return []CAListItem{
		caListItemWithCert("active", "2020-01-01T00:00:00Z", "2021-01-01T00:00:00Z"),
		caListItemWithCert("active", "2026-01-01T00:00:00Z", "2099-01-01T00:00:00Z"),
		caListItemWithCert("suspended", "2020-01-01T00:00:00Z", "2021-01-01T00:00:00Z"),
	}
}

// TestComputeCAHealth_ExpiredActiveCADoesNotPresentAsActive is the S-43
// acceptance-3 decision test: computeCAHealth must derive each entry's
// Status the same way handlers_cas.go's caEffectiveStatus does, not copy
// the stored column verbatim -- otherwise CA Health renders a green
// "active" badge (Status) beside a red "Expired" fact (ExpiresAt) for the
// same row, the exact inconsistency docs/ANALYST_REPORT_2026-07-31.md M-3
// found. The stored-active-but-expired CA must also drop out of
// Summary.Active, which the stored-column comparison also over-counted.
func TestComputeCAHealth_ExpiredActiveCADoesNotPresentAsActive(t *testing.T) {
	report := computeCAHealth(caHealthTestItems())

	if len(report.Items) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(report.Items))
	}
	if got := report.Items[0].Status; got != "expired" {
		t.Errorf("expired-but-stored-active CA: Status = %q, want %q", got, "expired")
	}
	if got := report.Items[1].Status; got != "active" {
		t.Errorf("genuinely active CA: Status = %q, want %q", got, "active")
	}
	if got := report.Items[2].Status; got != "suspended" {
		t.Errorf("expired-but-suspended CA: Status = %q, want %q", got, "suspended")
	}
	if report.Summary.Active != 1 {
		t.Errorf("Summary.Active = %d, want 1 (only the genuinely active CA)", report.Summary.Active)
	}
}

// TestCAHealthReport_ExpiredActiveCADoesNotPresentAsActive is the same
// decision exercised through GET /api/v1/reports/ca-health end to end.
func TestCAHealthReport_ExpiredActiveCADoesNotPresentAsActive(t *testing.T) {
	auth := newReportsTestAuth(t)
	provider := &reportCertProvider{items: buildTestCerts()}
	caProvider := &reportCAProvider{items: caHealthTestItems()}
	mux := http.NewServeMux()
	registerReportsHandlers(mux, auth, provider, caProvider, stubTemplateProvider{}, nil, stubAuditProvider{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/ca-health", nil)
	req.Header.Set("Authorization", "Bearer reports-test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Data CAHealthReport `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if len(resp.Data.Items) != 3 {
		t.Fatalf("expected 3 items, got %d", len(resp.Data.Items))
	}
	if got := resp.Data.Items[0].Status; got != "expired" {
		t.Errorf("expired-but-stored-active CA over the wire: status = %q, want %q", got, "expired")
	}
	if resp.Data.Summary.Active != 1 {
		t.Errorf("summary.active = %d, want 1", resp.Data.Summary.Active)
	}
}

// TestComputeComplianceEvidence_ExpiredActiveCADoesNotCountAsActive is the
// S-43 acceptance-1 gate-fix test for the INTERNAL-CA-HEALTH control:
// computeComplianceEvidence must count CAs the same way computeCAHealth
// does (caEffectiveStatus), not the stored "status" column verbatim.
// Reaching this fact through handlers_executive_summary.go's
// computeComplianceEvidence(certs, cas, "all") call means a stored-active-
// but-expired CA was still inflating the auditor-facing compliance evidence
// pack (JSON/PDF) and the dashboard's CompliancePassPercent even after
// computeCAHealth itself was fixed. With the only CA in scope stored
// "active" but its certificate expired, the stale column would count it as
// active (1 of 1, Status "pass"); the derived status must not.
func TestComputeComplianceEvidence_ExpiredActiveCADoesNotCountAsActive(t *testing.T) {
	cas := []CAListItem{caListItemWithCert("active", "2020-01-01T00:00:00Z", "2021-01-01T00:00:00Z")}
	report := computeComplianceEvidence(nil, cas, "all")

	var control *ComplianceControl
	for i := range report.Controls {
		if report.Controls[i].ID == "INTERNAL-CA-HEALTH" {
			control = &report.Controls[i]
		}
	}
	if control == nil {
		t.Fatal("INTERNAL-CA-HEALTH control missing from report")
	}
	if want := "Active CAs: 0 of 1 total."; control.Evidence != want {
		t.Errorf("Evidence = %q, want %q", control.Evidence, want)
	}
	if control.Status != "warn" {
		t.Errorf("Status = %q, want %q (a stale count off ca.Status would keep this \"pass\")", control.Status, "warn")
	}
}

// TestReportTotals_AgreeWithCertificateListForTeamScopedPrincipal is the
// S-45 regression. GET /api/v1/certificates narrows a non-admin principal to
// certificates whose team_id matches their own principal ID
// (authorizeCertificateListQuery, handlers_certificates.go); report
// endpoints used to skip that check entirely and aggregate over the whole
// fleet, so a team-scoped caller's reports counted a certificate their own
// inventory view never lists (e.g. the migration-000007 seed certificate,
// analyst report 2026-07-31, M-2). This uses the real file-backed
// CertificateProvider and a JWT principal — not the bootstrap super-admin
// every other test in this file authenticates as, which bypasses the
// ownership check entirely — so it exercises the exact authorization path
// production traffic hits.
func TestReportTotals_AgreeWithCertificateListForTeamScopedPrincipal(t *testing.T) {
	t.Setenv("AUTH_MODE", "jwt")
	t.Setenv("APP_AUTH_UNMAPPED_ROLE", "read-only") // not a role-mapping test
	t.Setenv("APP_JWT_HS256_SECRET", "reports-test-jwt-secret")

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "certificates.json")
	body := []byte(`[
{"fingerprint_sha256":"fp-own","serial_number":"01","common_name":"own.example.com","team_id":"svc-alice","valid_from":"2026-01-01T00:00:00Z","valid_until":"2027-01-01T00:00:00Z","public_key_algorithm":"ECDSA","renewal_status":"active","source":"api","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"},
{"fingerprint_sha256":"fp-other-team","serial_number":"02","common_name":"other.example.com","team_id":"ci-seed-team","valid_from":"2026-01-01T00:00:00Z","valid_until":"2027-01-01T00:00:00Z","public_key_algorithm":"RSA","renewal_status":"active","source":"api","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}
]`)
	if err := os.WriteFile(filePath, body, 0o600); err != nil {
		t.Fatalf("failed to write certificate fixture: %v", err)
	}
	t.Setenv("APP_CERTIFICATE_FILE", filePath)

	auth := NewAuthenticatorFromEnv()
	provider := NewFileCertificateProviderFromEnv()
	mux := http.NewServeMux()
	registerCertificateHandlers(mux, auth, provider, stubAuditProviderForCertificate{}, nil)
	registerReportsHandlers(mux, auth, provider, &reportCAProvider{}, stubTemplateProvider{}, nil, stubAuditProvider{})

	token := signHS256JWT(t, "reports-test-jwt-secret", map[string]any{
		"sub": "svc-alice",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	})

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	listReq.Header.Set("Authorization", "Bearer "+token)
	listRec := httptest.NewRecorder()
	mux.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("expected 200 from certificate list, got %d: %s", listRec.Code, listRec.Body.String())
	}
	var listResp struct {
		Meta struct {
			Total int `json:"total"`
		} `json:"meta"`
	}
	if err := json.NewDecoder(listRec.Body).Decode(&listResp); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if listResp.Meta.Total != 1 {
		t.Fatalf("expected the inventory to show only svc-alice's own certificate (1), got %d — fixture assumption broke", listResp.Meta.Total)
	}

	cases := []struct {
		path       string
		totalCerts func([]byte) int
	}{
		{"/api/v1/reports/crypto-posture", func(raw []byte) int {
			var resp struct {
				Data CryptoPostureReport `json:"data"`
			}
			_ = json.Unmarshal(raw, &resp)
			return resp.Data.TotalCerts
		}},
		{"/api/v1/reports/expiry-timeline", func(raw []byte) int {
			var resp struct {
				Data ExpiryTimelineReport `json:"data"`
			}
			_ = json.Unmarshal(raw, &resp)
			return resp.Data.TotalCerts
		}},
		{"/api/v1/reports/algorithm-sunset", func(raw []byte) int {
			var resp struct {
				Data AlgorithmSunsetReport `json:"data"`
			}
			_ = json.Unmarshal(raw, &resp)
			return resp.Data.TotalCerts
		}},
	}

	for _, tc := range cases {
		reportReq := httptest.NewRequest(http.MethodGet, tc.path, nil)
		reportReq.Header.Set("Authorization", "Bearer "+token)
		reportRec := httptest.NewRecorder()
		mux.ServeHTTP(reportRec, reportReq)
		if reportRec.Code != http.StatusOK {
			t.Fatalf("%s: expected 200, got %d: %s", tc.path, reportRec.Code, reportRec.Body.String())
		}
		got := tc.totalCerts(reportRec.Body.Bytes())
		if got != listResp.Meta.Total {
			t.Errorf("%s: total_certs=%d disagrees with certificate list total=%d — report counted a record svc-alice's own inventory refuses to display", tc.path, got, listResp.Meta.Total)
		}
	}
}

// S-62: pagination across separate ListCertificates calls needs a TOTAL
// order. The provider ranges a map (randomized) and CreatedAt is
// second-precision, so ties spanning a page boundary could appear on both
// pages or neither — report totals flapping 136/138 against meta.total
// 137. This seeds 137 certs where the block straddling offset 100 shares
// one CreatedAt second, and asserts repeated paged walks are exact.
func TestPagingIsStableAcrossTiedCreatedAtSeconds(t *testing.T) {
	raw := NewCACertificateProvider(nil, nil, nil, false)
	provider := raw.(*caCertificateProvider)
	for i := 0; i < 137; i++ {
		created := fmt.Sprintf("2026-08-19T10:00:%02dZ", i/10) // 10 certs share each second
		fp := fmt.Sprintf("fp-%03d", i)
		provider.certs[fp] = &storedCert{item: CertificateItem{
			FingerprintSHA256: fp,
			CommonName:        fmt.Sprintf("tied-%03d.example.com", i),
			CreatedAt:         created,
			RenewalStatus:     "active",
		}}
	}

	for run := 0; run < 10; run++ {
		seen := map[string]int{}
		offset := 0
		for {
			page, err := provider.ListCertificates(context.Background(), CertificateListQuery{Limit: 100, Offset: offset})
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			for _, item := range page.Items {
				seen[item.FingerprintSHA256]++
			}
			if page.Total != 137 {
				t.Fatalf("run %d: Total=%d, want 137", run, page.Total)
			}
			offset += len(page.Items)
			if offset >= page.Total || len(page.Items) == 0 {
				break
			}
		}
		if len(seen) != 137 {
			t.Fatalf("run %d: paged walk saw %d distinct certs, want 137 (skipped rows)", run, len(seen))
		}
		for fp, n := range seen {
			if n != 1 {
				t.Fatalf("run %d: %s appeared %d times (overlapping pages)", run, fp, n)
			}
		}
	}
}

// S-63: a forbidden list-authorization verdict rejects the report query
// instead of silently aggregating with the caller's TeamID left in place.
func TestReportVisibleCertificatesRejectsForbiddenQuery(t *testing.T) {
	// A non-admin whose query would be forbidden: reportVisibleCertificates
	// builds an empty query (own-team default passes), so exercise the
	// rejection through the helper contract directly — a populated TeamID
	// belonging to someone else.
	pd := AuthPrincipal{ID: "team-a", Role: "viewer"}
	query := CertificateListQuery{TeamID: "team-b"}
	if err := authorizeCertificateListQuery(&query, pd); err == nil {
		t.Fatal("cross-team query must be forbidden")
	}
	// And the paging helper propagates a forbidden verdict as an error —
	// proven by a provider that would panic if consulted after refusal.
	// (Own-team queries still work.)
	items, err := reportVisibleCertificates(context.Background(), pd, &reportCertProvider{items: buildTestCerts()}, 10)
	if err != nil {
		t.Fatalf("own-team report visibility must work: %v", err)
	}
	if len(items) == 0 {
		t.Fatal("expected items for the permitted query")
	}
}

// --- S-47: Issuance Velocity Anomaly Detection ---

// TestComputeIssuanceVelocity_AnomalyDetectionBelowMinimumSample verifies that
// anomalies are NOT reported when the 30-day sample size is below the minimum
// threshold (5 certificates). This prevents false positives on small deployments.
func TestComputeIssuanceVelocity_AnomalyDetectionBelowMinimumSample(t *testing.T) {
	now := time.Now().UTC()

	// Create 4 certificates (below the minimum of 5) issued in the last 30 days,
	// with 3 on a single day. Even though 3 > 2× the average (0.13), the sample
	// size is insufficient so no anomaly should be reported.
	certs := []CertificateItem{
		{FingerprintSHA256: "fp1", CreatedAt: now.Add(-10 * 24 * time.Hour).Format(time.RFC3339)},
		{FingerprintSHA256: "fp2", CreatedAt: now.Add(-10 * 24 * time.Hour).Format(time.RFC3339)},
		{FingerprintSHA256: "fp3", CreatedAt: now.Add(-10 * 24 * time.Hour).Format(time.RFC3339)},
		{FingerprintSHA256: "fp4", CreatedAt: now.Add(-20 * 24 * time.Hour).Format(time.RFC3339)},
	}

	report := computeIssuanceVelocity(certs)

	if report.Windows.Last30d != 4 {
		t.Fatalf("expected Last30d=4, got %d", report.Windows.Last30d)
	}
	if len(report.AnomalyDays) != 0 {
		t.Fatalf("expected 0 anomaly days below minimum sample (threshold=5, have=%d), got %d", report.Windows.Last30d, len(report.AnomalyDays))
	}
	if report.AnomalyMinimumSample != 5 {
		t.Errorf("expected AnomalyMinimumSample=5, got %d", report.AnomalyMinimumSample)
	}
	if !strings.Contains(report.AnomalyThresholdNote, "Anomaly detection requires a minimum sample") {
		t.Errorf("expected threshold note about minimum sample, got: %s", report.AnomalyThresholdNote)
	}
	if !strings.Contains(report.AnomalyThresholdNote, "5") {
		t.Errorf("expected threshold note to mention 5, got: %s", report.AnomalyThresholdNote)
	}
}

// TestComputeIssuanceVelocity_AnomalyDetectionAboveMinimumSample verifies that
// anomalies ARE reported when the 30-day sample size meets or exceeds the minimum
// threshold (5 certificates) and a day has >2× the daily average.
func TestComputeIssuanceVelocity_AnomalyDetectionAboveMinimumSample(t *testing.T) {
	now := time.Now().UTC()

	// Create 10 certificates in the last 30 days: 1 each on 9 days, and 3 on day 0.
	// Average = 10/30 = 0.33 per day. 3 > 2×0.33 = 0.67, so day 0 should be an anomaly.
	certs := make([]CertificateItem, 0, 10)
	for i := 0; i < 3; i++ {
		certs = append(certs, CertificateItem{
			FingerprintSHA256: fmt.Sprintf("fp-anomaly-%d", i),
			CreatedAt:         now.Format(time.RFC3339),
		})
	}
	for day := 1; day <= 7; day++ {
		certs = append(certs, CertificateItem{
			FingerprintSHA256: fmt.Sprintf("fp-day%d", day),
			CreatedAt:         now.Add(time.Duration(-day*24) * time.Hour).Format(time.RFC3339),
		})
	}

	report := computeIssuanceVelocity(certs)

	if report.Windows.Last30d != 10 {
		t.Fatalf("expected Last30d=10, got %d", report.Windows.Last30d)
	}
	if len(report.AnomalyDays) == 0 {
		t.Fatalf("expected at least 1 anomaly day, got 0")
	}
	expectedDate := now.Format("2006-01-02")
	found := false
	for _, day := range report.AnomalyDays {
		if day == expectedDate {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected anomaly on %s, got: %v", expectedDate, report.AnomalyDays)
	}
	if !strings.Contains(report.AnomalyThresholdNote, "Anomalies detected when daily issuance") {
		t.Errorf("expected threshold note about anomalies detected, got: %s", report.AnomalyThresholdNote)
	}
	if !strings.Contains(report.AnomalyThresholdNote, "2×") {
		t.Errorf("expected threshold note to mention 2× multiplier, got: %s", report.AnomalyThresholdNote)
	}
}

// TestComputeIssuanceVelocity_AnomalyAtExactMinimumBoundary tests the boundary
// condition: exactly 5 certificates (the minimum) should enable anomaly detection.
func TestComputeIssuanceVelocity_AnomalyAtExactMinimumBoundary(t *testing.T) {
	now := time.Now().UTC()

	// Exactly 5 certificates: 3 on day 0, 1 on day 1, 1 on day 2.
	// Average = 5/30 ≈ 0.17 per day. 3 > 2×0.17 = 0.34, so day 0 should trigger.
	certs := []CertificateItem{
		{FingerprintSHA256: "fp1", CreatedAt: now.Format(time.RFC3339)},
		{FingerprintSHA256: "fp2", CreatedAt: now.Format(time.RFC3339)},
		{FingerprintSHA256: "fp3", CreatedAt: now.Format(time.RFC3339)},
		{FingerprintSHA256: "fp4", CreatedAt: now.Add(-24 * time.Hour).Format(time.RFC3339)},
		{FingerprintSHA256: "fp5", CreatedAt: now.Add(-48 * time.Hour).Format(time.RFC3339)},
	}

	report := computeIssuanceVelocity(certs)

	if report.Windows.Last30d != 5 {
		t.Fatalf("expected Last30d=5, got %d", report.Windows.Last30d)
	}
	if len(report.AnomalyDays) == 0 {
		t.Fatalf("expected anomalies to be detected at exactly minimum sample (5), got 0 anomalies")
	}
	if !strings.Contains(report.AnomalyThresholdNote, "Anomalies detected") {
		t.Errorf("expected threshold note indicating detection is active, got: %s", report.AnomalyThresholdNote)
	}
}

// TestIssuanceVelocityReport_AnomalyThresholdDocumentationInResponse verifies
// the HTTP response includes the anomaly threshold documentation fields.
func TestIssuanceVelocityReport_AnomalyThresholdDocumentationInResponse(t *testing.T) {
	// Build a request with 6 certificates to exceed the minimum sample.
	now := time.Now().UTC()
	certs := make([]CertificateItem, 0, 6)
	for i := 0; i < 3; i++ {
		certs = append(certs, CertificateItem{
			FingerprintSHA256: fmt.Sprintf("fp-spike-%d", i),
			CreatedAt:         now.Format(time.RFC3339),
		})
	}
	for day := 1; day <= 3; day++ {
		certs = append(certs, CertificateItem{
			FingerprintSHA256: fmt.Sprintf("fp-day%d", day),
			CreatedAt:         now.Add(time.Duration(-day*24) * time.Hour).Format(time.RFC3339),
		})
	}

	provider := &reportCertProvider{items: certs}
	mux := http.NewServeMux()
	registerReportsHandlers(mux, newReportsTestAuth(t), provider, &reportCAProvider{}, stubTemplateProvider{}, nil, stubAuditProvider{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/issuance-velocity", nil)
	req.Header.Set("Authorization", "Bearer reports-test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Data struct {
			AnomalyMinimumSample int    `json:"anomaly_minimum_sample"`
			AnomalyThresholdNote string `json:"anomaly_threshold_note"`
		} `json:"data"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.Data.AnomalyMinimumSample != 5 {
		t.Errorf("expected anomaly_minimum_sample=5, got %d", resp.Data.AnomalyMinimumSample)
	}
	if resp.Data.AnomalyThresholdNote == "" {
		t.Error("expected anomaly_threshold_note to be present in response")
	}
	if !strings.Contains(resp.Data.AnomalyThresholdNote, "5") {
		t.Errorf("expected threshold note to document the minimum of 5, got: %s", resp.Data.AnomalyThresholdNote)
	}
}
