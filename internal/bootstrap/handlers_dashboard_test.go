// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestDashboardSummaryCarriesFindingFunnel is the W2-11 regression for
// acceptance criterion 4: GET /api/v1/dashboard/summary built a bespoke
// anonymous response struct that never copied DiscoverySummary.Findings
// onto the wire, so a caller of the live API could not see raw/effective/
// suppressed even after the provider computed them. This asserts the
// counts round-trip through the actual HTTP response body, not just the
// provider return value.
func TestDashboardSummaryCarriesFindingFunnel(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	RegisterHandlers(mux, auth,
		stubCertSummaryProvider{snapshot: CertSummarySnapshot{Total: 12, Source: "file-store"}},
		stubAuditProvider{}, stubCAProvider{}, stubTemplateProvider{},
		NewFileCertificateProviderFromEnv(), NewProtocolProviderFromEnv(),
		stubDiscoveryProvider{summary: DiscoverySummary{
			DiscoveredEndpoints: 20,
			RiskyEndpoints:      5,
			ActiveScanJobs:      1,
			Findings:            FindingFunnelSummary{Raw: 9, Effective: 6, Suppressed: 3},
		}},
		stubNotificationProvider{}, stubDashboardActionProvider{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/summary", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rec.Code, rec.Body.String())
	}

	var body struct {
		Data struct {
			Discovery struct {
				Findings FindingFunnelSummary `json:"findings"`
			} `json:"discovery"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	got := body.Data.Discovery.Findings
	want := FindingFunnelSummary{Raw: 9, Effective: 6, Suppressed: 3}
	if got != want {
		t.Fatalf("expected discovery.findings %+v on the wire, got %+v (body: %s)", want, got, rec.Body.String())
	}
}
