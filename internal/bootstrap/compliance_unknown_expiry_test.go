// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// failingCAProvider fails ListCAs; every other method comes from the
// embedded nil interface and must not be reached.
type failingCAProvider struct{ CAProvider }

func (failingCAProvider) ListCAs(context.Context, CAListQuery) (CAListResult, error) {
	return CAListResult{}, errors.New("ca store down")
}

func soc2Control(t *testing.T, certs []CertificateItem, now time.Time) ComplianceControl {
	t.Helper()
	report := computeComplianceEvidenceAt(certs, nil, "soc2", now)
	for _, c := range report.Controls {
		if c.ID == "SOC2-CC6.7" {
			return c
		}
	}
	t.Fatal("SOC2-CC6.7 missing")
	return ComplianceControl{}
}

func TestSOC2LifecycleControl_UnknownExpiryIsNotPass(t *testing.T) {
	now := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
	healthy := CertificateItem{ValidUntil: now.Add(200 * 24 * time.Hour).Format(time.RFC3339)}

	cases := []struct {
		name       string
		certs      []CertificateItem
		wantStatus string
		wantEvid   string
	}{
		{"all healthy passes", []CertificateItem{healthy, healthy}, "pass", "Unknown expiry: 0."},
		{"empty expiry blocks pass", []CertificateItem{healthy, {ValidUntil: ""}}, "warn", "Unknown expiry: 1."},
		{"unparseable expiry blocks pass", []CertificateItem{healthy, {ValidUntil: "next tuesday"}}, "warn", "Unknown expiry: 1."},
		{"expired still fails", []CertificateItem{healthy, {ValidUntil: now.Add(-time.Hour).Format(time.RFC3339)}}, "fail", "Expired: 1."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := soc2Control(t, tc.certs, now)
			if c.Status != tc.wantStatus {
				t.Errorf("status = %q, want %q (evidence %q)", c.Status, tc.wantStatus, c.Evidence)
			}
			if !strings.Contains(c.Evidence, tc.wantEvid) {
				t.Errorf("evidence %q missing %q", c.Evidence, tc.wantEvid)
			}
		})
	}

	c := soc2Control(t, []CertificateItem{{ValidUntil: ""}}, now)
	if !strings.Contains(c.Remediation, "missing or unparseable expiry") {
		t.Errorf("remediation should name the unknown-expiry gap, got %q", c.Remediation)
	}
}

func TestTallyExpiry_ParsesOncePerCertAndBuckets(t *testing.T) {
	now := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
	got := tallyExpiry([]CertificateItem{
		{ValidUntil: now.Add(-time.Hour).Format(time.RFC3339)},
		{ValidUntil: now.Add(24 * time.Hour).Format(time.RFC3339)},
		{ValidUntil: now.Add(90 * 24 * time.Hour).Format(time.RFC3339)},
		{ValidUntil: ""},
		{ValidUntil: "garbage"},
	}, now)
	if got != (expiryTally{expired: 1, expiring30: 1, unknown: 2}) {
		t.Errorf("tally = %+v", got)
	}
}

func TestRenderEvidencePack_ListCAsErrorFailsInsteadOfOmittingCAs(t *testing.T) {
	certs := &reportCertProvider{items: buildTestCerts()}
	_, _, err := renderEvidencePackForFramework(context.Background(), certs, failingCAProvider{}, "all", time.Now())
	if err == nil || !strings.Contains(err.Error(), "ca store down") {
		t.Fatalf("want ListCAs error surfaced, got %v", err)
	}
}

func TestExecutiveSummaryHandler_ListCAsErrorIs503(t *testing.T) {
	auth := newReportsTestAuth(t)
	mux := http.NewServeMux()
	registerExecutiveSummaryHandler(mux, auth, &reportCertProvider{items: buildTestCerts()}, failingCAProvider{}, nil, stubAuditProvider{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/executive-summary", nil)
	req.Header.Set("Authorization", "Bearer reports-test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (body %s)", rec.Code, rec.Body.String())
	}
}

func TestComplianceEvidenceHandler_ListCAsErrorIs503(t *testing.T) {
	auth := newReportsTestAuth(t)
	mux := http.NewServeMux()
	registerReportsHandlers(mux, auth, &reportCertProvider{items: buildTestCerts()}, failingCAProvider{}, stubTemplateProvider{}, nil, stubAuditProvider{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/compliance-evidence?framework=all", nil)
	req.Header.Set("Authorization", "Bearer reports-test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (body %s)", rec.Code, rec.Body.String())
	}
}
