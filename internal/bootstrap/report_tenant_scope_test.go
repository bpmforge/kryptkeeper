// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestFilterableReportsScopeByTenant is the W2-03 regression for the
// filterable report families: a scoped principal (acme) sees only their own
// tenant's CAs/certs in ca-health and algorithm-sunset, while an unscoped
// super-admin (bootstrap, no X-Tenant) sees the whole fleet. Reuses the
// setupTenantWritePathTest fixture (2 CAs/2 certs, one per tenant) since it
// already wires the full handler stack including reports.
func TestFilterableReportsScopeByTenant(t *testing.T) {
	mux, acmeToken, _ := setupTenantWritePathTest(t)

	acmeCAHealth := doTenantReq(mux, http.MethodGet, "/api/v1/reports/ca-health", acmeToken, "acme")
	if acmeCAHealth.Code != http.StatusOK {
		t.Fatalf("acme ca-health: expected 200, got %d: %s", acmeCAHealth.Code, acmeCAHealth.Body.String())
	}
	var acmeCAResp struct {
		Data CAHealthReport `json:"data"`
	}
	if err := json.NewDecoder(acmeCAHealth.Body).Decode(&acmeCAResp); err != nil {
		t.Fatalf("decode acme ca-health: %v", err)
	}
	if acmeCAResp.Data.TotalCAs != 1 {
		t.Fatalf("expected acme to see 1 CA (its own), got %d", acmeCAResp.Data.TotalCAs)
	}

	rootReq := httptest.NewRequest(http.MethodGet, "/api/v1/reports/ca-health", nil)
	rootReq.Header.Set("Authorization", "Bearer root-token")
	rootRec := httptest.NewRecorder()
	mux.ServeHTTP(rootRec, rootReq)
	if rootRec.Code != http.StatusOK {
		t.Fatalf("super-admin ca-health: expected 200, got %d: %s", rootRec.Code, rootRec.Body.String())
	}
	var rootCAResp struct {
		Data CAHealthReport `json:"data"`
	}
	if err := json.NewDecoder(rootRec.Body).Decode(&rootCAResp); err != nil {
		t.Fatalf("decode super-admin ca-health: %v", err)
	}
	if rootCAResp.Data.TotalCAs != 2 {
		t.Fatalf("expected unscoped super-admin to see both CAs, got %d", rootCAResp.Data.TotalCAs)
	}

	acmeSunset := doTenantReq(mux, http.MethodGet, "/api/v1/reports/algorithm-sunset", acmeToken, "acme")
	if acmeSunset.Code != http.StatusOK {
		t.Fatalf("acme algorithm-sunset: expected 200, got %d: %s", acmeSunset.Code, acmeSunset.Body.String())
	}
	var acmeSunsetResp struct {
		Data AlgorithmSunsetReport `json:"data"`
	}
	if err := json.NewDecoder(acmeSunset.Body).Decode(&acmeSunsetResp); err != nil {
		t.Fatalf("decode acme algorithm-sunset: %v", err)
	}
	if acmeSunsetResp.Data.TotalCerts != 1 {
		t.Fatalf("expected acme to see 1 cert (its own), got %d", acmeSunsetResp.Data.TotalCerts)
	}
}

// TestAggregateReportEndpointsDenyTenantScoped is the W2-03/D-027 regression
// for the aggregate-super-admin-only branch: dashboard/summary, the posture
// trend, the evidence schedule list, the PQC countdown, and (W2-07) the
// renewal-SLO report all 403 a tenant-scoped principal (even one with the
// pki-admin role, which otherwise passes canReadOperationalSummaries), while
// an unscoped super-admin is let through.
func TestAggregateReportEndpointsDenyTenantScoped(t *testing.T) {
	mux, acmeToken, _ := setupTenantWritePathTest(t)

	aggregateGETs := []string{
		"/api/v1/dashboard/summary",
		"/api/v1/reports/crypto-posture/trend",
		"/api/v1/reports/evidence/schedules",
		"/api/v1/reports/pqc-countdown",
		"/api/v1/reports/pqc-waves",
		"/api/v1/reports/renewal-slo",
	}
	for _, path := range aggregateGETs {
		rec := doTenantReq(mux, http.MethodGet, path, acmeToken, "acme")
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: expected 403 for tenant-scoped principal, got %d: %s", path, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "D-102") {
			t.Errorf("%s: expected 403 body to cite the D-102 aggregate-super-admin-only decision, got: %s", path, rec.Body.String())
		}

		rootReq := httptest.NewRequest(http.MethodGet, path, nil)
		rootReq.Header.Set("Authorization", "Bearer root-token")
		rootRec := httptest.NewRecorder()
		mux.ServeHTTP(rootRec, rootReq)
		if rootRec.Code == http.StatusForbidden {
			t.Errorf("%s: unscoped super-admin should not be denied, got 403: %s", path, rootRec.Body.String())
		}
	}
}

// changeAuditTestAuditProvider is a minimal AuditProvider stub returning
// fixed entries tagged with distinct Tenant values, for proving change-audit
// report filtering (AuditEntry carries its own Tenant, no store lookup).
type changeAuditTestAuditProvider struct {
	entries []AuditEntry
}

func (p *changeAuditTestAuditProvider) ListEntries(_ context.Context, _ AuditListQuery) (AuditListResult, error) {
	return AuditListResult{Entries: p.entries, Total: len(p.entries)}, nil
}
func (p *changeAuditTestAuditProvider) AppendEntry(_ context.Context, _ AuditEntry) error { return nil }

// TestChangeAuditReportScopesByTenant is the W2-03 regression for the one
// report family backed by AuditEntry rather than CertificateItem/CAListItem:
// change-audit must filter by each entry's own stamped Tenant field, with no
// store lookup needed.
func TestChangeAuditReportScopesByTenant(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "root-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32-chars-minimum!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	t.Setenv("MULTI_TENANCY", "on")

	now := time.Now().UTC().Format(time.RFC3339)
	auditProvider := &changeAuditTestAuditProvider{entries: []AuditEntry{
		{Action: "ca.create", ResourceType: "ca", ResourceID: "ca-acme", Outcome: "success", Tenant: "acme", Timestamp: now},
		{Action: "ca.create", ResourceType: "ca", ResourceID: "ca-globex", Outcome: "success", Tenant: "globex", Timestamp: now},
	}}

	auth := NewAuthenticatorFromEnv()
	_, acmeToken, err := auth.CreateAPIKey("acme-svc", "svc-principal", "pki-admin", []string{"*"}, "", "acme", time.Now())
	if err != nil {
		t.Fatalf("create acme api key: %v", err)
	}

	mux := http.NewServeMux()
	registerReportsHandlers(mux, auth, &reportCertProvider{}, &reportCAProvider{}, stubTemplateProvider{}, nil, auditProvider)

	acmeRec := doTenantReq(mux, http.MethodGet, "/api/v1/reports/change-audit", acmeToken, "acme")
	if acmeRec.Code != http.StatusOK {
		t.Fatalf("acme change-audit: expected 200, got %d: %s", acmeRec.Code, acmeRec.Body.String())
	}
	var acmeResp struct {
		Data ChangeAuditReport `json:"data"`
	}
	if err := json.NewDecoder(acmeRec.Body).Decode(&acmeResp); err != nil {
		t.Fatalf("decode acme change-audit: %v", err)
	}
	if acmeResp.Data.TotalEvents != 1 {
		t.Fatalf("expected acme to see 1 audit event (its own), got %d", acmeResp.Data.TotalEvents)
	}

	rootReq := httptest.NewRequest(http.MethodGet, "/api/v1/reports/change-audit", nil)
	rootReq.Header.Set("Authorization", "Bearer root-token")
	rootRec := httptest.NewRecorder()
	mux.ServeHTTP(rootRec, rootReq)
	if rootRec.Code != http.StatusOK {
		t.Fatalf("super-admin change-audit: expected 200, got %d: %s", rootRec.Code, rootRec.Body.String())
	}
	var rootResp struct {
		Data ChangeAuditReport `json:"data"`
	}
	if err := json.NewDecoder(rootRec.Body).Decode(&rootResp); err != nil {
		t.Fatalf("decode super-admin change-audit: %v", err)
	}
	if rootResp.Data.TotalEvents != 2 {
		t.Fatalf("expected unscoped super-admin to see both audit events, got %d", rootResp.Data.TotalEvents)
	}
}
