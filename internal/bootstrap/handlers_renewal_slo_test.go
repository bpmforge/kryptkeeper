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

	"kryptkeeper/internal/metrics"
)

// lookupCertProvider extends reportCertProvider with a working GetCertificate
// (the base stub always reports not-found), so MTTR correlation can be tested.
type lookupCertProvider struct {
	*reportCertProvider
}

func (p *lookupCertProvider) GetCertificate(_ context.Context, fp string) (CertificateDetail, bool, error) {
	for _, it := range p.items {
		if it.FingerprintSHA256 == fp {
			return CertificateDetail{CertificateItem: it}, true, nil
		}
	}
	return CertificateDetail{}, false, nil
}

// seedAgentWithResults registers an agent and records the given results.
func seedAgentWithResults(t *testing.T, store AgentStore, name string, results []AgentRenewalResult) string {
	t.Helper()
	id, token, err := store.register(name, AgentTypeLinux)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	for _, r := range results {
		if err := store.submitRenewalResult(id, token, r); err != nil {
			t.Fatalf("submit result: %v", err)
		}
	}
	return id
}

func TestRenewalSLO_AggregatesOutcomes(t *testing.T) {
	resetRenewalRetryStateForTest()
	t.Cleanup(resetRenewalRetryStateForTest)
	auth := newReportsTestAuth(t)
	store := NewAgentStore()
	seedAgentWithResults(t, store, "a1", []AgentRenewalResult{
		{TaskID: "t1", Fingerprint: "fp1", Outcome: "installed_verified", ReportedAt: "2026-06-16T10:00:00Z"},
		{TaskID: "t2", Fingerprint: "fp2", Outcome: "installed_verified", ReportedAt: "2026-06-16T11:00:00Z"},
		{TaskID: "t3", Fingerprint: "fp3", Outcome: "verify_failed", RolledBack: true, Detail: "mismatch", ReportedAt: "2026-06-16T12:00:00Z"},
	})

	mux := http.NewServeMux()
	registerRenewalSLOHandler(mux, auth, store, &reportCertProvider{}, stubAuditProvider{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/renewal-slo", nil)
	req.Header.Set("Authorization", "Bearer reports-test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data RenewalSLOReport `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	d := resp.Data
	if d.TotalRenewals != 3 {
		t.Fatalf("total renewals: got %d, want 3", d.TotalRenewals)
	}
	if d.SuccessRatePercent != 66 {
		t.Errorf("success rate: got %d, want 66", d.SuccessRatePercent)
	}
	if d.Outcomes["installed_verified"] != 2 || d.Outcomes["verify_failed"] != 1 {
		t.Errorf("outcome counts wrong: %+v", d.Outcomes)
	}
	if len(d.FailedRenewals) != 1 || d.FailedRenewals[0].TaskID != "t3" {
		t.Fatalf("failed-renewal queue wrong: %+v", d.FailedRenewals)
	}
	if d.AgentsTotal != 1 {
		t.Errorf("agents total: got %d", d.AgentsTotal)
	}
}

func TestRenewalSLO_ComputesMTTRFromInventory(t *testing.T) {
	resetRenewalRetryStateForTest()
	t.Cleanup(resetRenewalRetryStateForTest)
	auth := newReportsTestAuth(t)
	store := NewAgentStore()
	// Renewed cert fp-mttr became valid at 10:00; agent verified at 10:05 → 300s.
	seedAgentWithResults(t, store, "a1", []AgentRenewalResult{
		{TaskID: "t1", Fingerprint: "fp-mttr", Outcome: "installed_verified", ReportedAt: "2026-06-16T10:05:00Z"},
	})
	certs := &lookupCertProvider{reportCertProvider: &reportCertProvider{items: []CertificateItem{
		{FingerprintSHA256: "fp-mttr", ValidFrom: "2026-06-16T10:00:00Z"},
	}}}

	mux := http.NewServeMux()
	registerRenewalSLOHandler(mux, auth, store, certs, stubAuditProvider{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/renewal-slo", nil)
	req.Header.Set("Authorization", "Bearer reports-test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp struct {
		Data RenewalSLOReport `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Data.MTTRSamples != 1 {
		t.Fatalf("expected 1 MTTR sample, got %d", resp.Data.MTTRSamples)
	}
	if resp.Data.MeanTimeToRenewSecs != 300 {
		t.Errorf("MTTR: got %d, want 300", resp.Data.MeanTimeToRenewSecs)
	}
}

func TestRenewalSLO_EmptyWhenNoAgents(t *testing.T) {
	resetRenewalRetryStateForTest()
	t.Cleanup(resetRenewalRetryStateForTest)
	auth := newReportsTestAuth(t)
	store := NewAgentStore()
	mux := http.NewServeMux()
	registerRenewalSLOHandler(mux, auth, store, &reportCertProvider{}, stubAuditProvider{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/renewal-slo", nil)
	req.Header.Set("Authorization", "Bearer reports-test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp struct {
		Data RenewalSLOReport `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Data.TotalRenewals != 0 || len(resp.Data.FailedRenewals) != 0 {
		t.Errorf("expected empty SLO, got %+v", resp.Data)
	}
}

func TestRenewalSLO_RequiresAuth(t *testing.T) {
	auth := newReportsTestAuth(t)
	store := NewAgentStore()
	mux := http.NewServeMux()
	registerRenewalSLOHandler(mux, auth, store, &reportCertProvider{}, stubAuditProvider{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/renewal-slo", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestRenewalSLO_FailedQueueReflectsLatestPerCert(t *testing.T) {
	resetRenewalRetryStateForTest()
	t.Cleanup(resetRenewalRetryStateForTest)
	auth := newReportsTestAuth(t)
	store := NewAgentStore()
	// fp-flaky failed first, then auto-retried to success → must NOT appear in
	// the failed queue. fp-bad is still failing → must appear.
	seedAgentWithResults(t, store, "a1", []AgentRenewalResult{
		{TaskID: "t1", Fingerprint: "fp-flaky", Outcome: "verify_failed", RolledBack: true, ReportedAt: "2026-06-16T10:00:00Z"},
		{TaskID: "t2", Fingerprint: "fp-flaky", Outcome: "installed_verified", ReportedAt: "2026-06-16T11:00:00Z"},
		{TaskID: "t3", Fingerprint: "fp-bad", Outcome: "reload_failed", RolledBack: true, ReportedAt: "2026-06-16T12:00:00Z"},
	})

	mux := http.NewServeMux()
	registerRenewalSLOHandler(mux, auth, store, &reportCertProvider{}, stubAuditProvider{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/renewal-slo", nil)
	req.Header.Set("Authorization", "Bearer reports-test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp struct {
		Data RenewalSLOReport `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Data.FailedRenewals) != 1 {
		t.Fatalf("expected 1 current failure (fp-bad), got %d: %+v", len(resp.Data.FailedRenewals), resp.Data.FailedRenewals)
	}
	if resp.Data.FailedRenewals[0].Fingerprint != "fp-bad" {
		t.Errorf("expected fp-bad in queue, got %s", resp.Data.FailedRenewals[0].Fingerprint)
	}
	// Historical activity still counts all 3 attempts.
	if resp.Data.TotalRenewals != 3 {
		t.Errorf("expected 3 total renewals (historical), got %d", resp.Data.TotalRenewals)
	}
}

// TestRenewalSLO_IncludesSchedulerDeadLetters is the W2-07 regression: a
// renewal-notification trigger the scheduler dead-lettered (a distinct
// failure domain from agent-reported renewal outcomes) must appear in this
// same report's FailedRenewals queue, not only in scheduler logs.
func TestRenewalSLO_IncludesSchedulerDeadLetters(t *testing.T) {
	resetRenewalRetryStateForTest()
	t.Cleanup(resetRenewalRetryStateForTest)

	auth := newReportsTestAuth(t)
	store := NewAgentStore()
	seedAgentWithResults(t, store, "a1", []AgentRenewalResult{
		{TaskID: "t1", Fingerprint: "fp-agent-bad", Outcome: "reload_failed", RolledBack: true, ReportedAt: "2026-06-16T12:00:00Z"},
	})

	for i := 0; i < renewalTriggerMaxAttempts; i++ {
		recordRenewalTriggerFailure("fp-notif-stuck", "smtp: connection refused")
	}

	mux := http.NewServeMux()
	registerRenewalSLOHandler(mux, auth, store, &reportCertProvider{}, stubAuditProvider{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/renewal-slo", nil)
	req.Header.Set("Authorization", "Bearer reports-test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp struct {
		Data RenewalSLOReport `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Data.FailedRenewals) != 2 {
		t.Fatalf("expected 2 failures (1 agent-reported + 1 scheduler dead-letter), got %d: %+v", len(resp.Data.FailedRenewals), resp.Data.FailedRenewals)
	}
	var sawAgentFailure, sawDeadLetter bool
	for _, f := range resp.Data.FailedRenewals {
		if f.Fingerprint == "fp-agent-bad" {
			sawAgentFailure = true
		}
		if f.Fingerprint == "fp-notif-stuck" && f.Outcome == "notification_dead_letter" {
			sawDeadLetter = true
		}
	}
	if !sawAgentFailure {
		t.Error("expected the pre-existing agent-reported failure to still be present")
	}
	if !sawDeadLetter {
		t.Error("expected the scheduler's notification dead-letter to be present")
	}
}

// publishTestSLOBudget publishes a fixed snapshot built through the real SLOSet
// math and restores the previous one on cleanup.
func publishTestSLOBudget(t *testing.T) {
	t.Helper()
	prev := latestSLOStatus()
	t.Cleanup(func() { publishSLOStatus(prev) })
	good, bad := &metrics.Counter{}, &metrics.Counter{}
	set := metrics.NewSLOSet(
		metrics.RatioSLO("renewal-success-rate", "t", 0.99, good, bad),
		metrics.RatioSLO("issuance-success-rate", "t", 0.995, &metrics.Counter{}, &metrics.Counter{}),
	)
	t0 := time.Now().Add(-30 * time.Minute)
	set.Observe(t0)
	good.Add(90)
	bad.Add(10)
	publishSLOStatus(set.Status(time.Now()))
}

func TestStatusExposedOnAPI(t *testing.T) {
	publishTestSLOBudget(t)
	auth := newReportsTestAuth(t)
	mux := http.NewServeMux()
	registerRenewalSLOHandler(mux, auth, NewAgentStore(), &reportCertProvider{}, stubAuditProvider{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/renewal-slo", nil)
	req.Header.Set("Authorization", "Bearer reports-test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var raw struct {
		Data struct {
			SLOs []map[string]any `json:"slos"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(raw.Data.SLOs) != 2 {
		t.Fatalf("expected both ratio SLOs, got %v", raw.Data.SLOs)
	}
	for _, f := range []string{"name", "objective", "window_days", "has_data", "budget_remaining_pct", "burn_rate_1h", "burn_rate_6h", "breached"} {
		if _, ok := raw.Data.SLOs[0][f]; !ok {
			t.Errorf("slos[0] missing field %q: %v", f, raw.Data.SLOs[0])
		}
	}
	if raw.Data.SLOs[0]["name"] != "renewal-success-rate" || raw.Data.SLOs[0]["breached"] != true || raw.Data.SLOs[0]["window_days"] != float64(30) {
		t.Errorf("unexpected renewal SLO view: %v", raw.Data.SLOs[0])
	}
	if raw.Data.SLOs[1]["has_data"] != false || raw.Data.SLOs[1]["budget_remaining_pct"] != float64(100) {
		t.Errorf("idle SLO must report no data and full budget: %v", raw.Data.SLOs[1])
	}
}

func TestStatusEmptySliceBeforeFirstTick(t *testing.T) {
	prev := latestSLOStatus()
	publishSLOStatus(nil)
	t.Cleanup(func() { publishSLOStatus(prev) })
	auth := newReportsTestAuth(t)
	mux := http.NewServeMux()
	registerRenewalSLOHandler(mux, auth, NewAgentStore(), &reportCertProvider{}, stubAuditProvider{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/reports/renewal-slo", nil)
	req.Header.Set("Authorization", "Bearer reports-test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), `"slos":[]`) {
		t.Fatalf("slos must be [] not null before the first tick: %s", rec.Body.String())
	}
}

// TestStatusBudgetFieldsStayAggregateSuperAdminOnly proves the D-102 gate
// covers the W30-05 fields: a tenant-scoped principal gets 403 and none of the
// budget data, while the unscoped super-admin sees it.
func TestStatusBudgetFieldsStayAggregateSuperAdminOnly(t *testing.T) {
	publishTestSLOBudget(t)
	mux, acmeToken, _ := setupTenantWritePathTest(t)

	rec := doTenantReq(mux, http.MethodGet, "/api/v1/reports/renewal-slo", acmeToken, "acme")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("tenant-scoped: expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
	for _, leak := range []string{"slos", "budget_remaining_pct", "burn_rate_1h", "renewal-success-rate"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Errorf("403 body leaks %q: %s", leak, rec.Body.String())
		}
	}

	rootReq := httptest.NewRequest(http.MethodGet, "/api/v1/reports/renewal-slo", nil)
	rootReq.Header.Set("Authorization", "Bearer root-token")
	rootRec := httptest.NewRecorder()
	mux.ServeHTTP(rootRec, rootReq)
	if rootRec.Code != http.StatusOK || !strings.Contains(rootRec.Body.String(), "budget_remaining_pct") {
		t.Fatalf("super-admin: expected 200 with budget fields, got %d: %s", rootRec.Code, rootRec.Body.String())
	}
}
