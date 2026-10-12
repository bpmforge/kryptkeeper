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
)

type failingCertSummaryProvider struct{ err error }

func (failingCertSummaryProvider) LoadSummary(context.Context) (CertSummarySnapshot, error) {
	return CertSummarySnapshot{}, errors.New("summary unavailable")
}

type failingDiscoveryProvider struct{ err error }

func (failingDiscoveryProvider) GetSummary(context.Context) (DiscoverySummary, error) {
	return DiscoverySummary{}, errors.New("discovery unavailable")
}
func (failingDiscoveryProvider) ListEndpoints(context.Context, DiscoveryEndpointQuery) (DiscoveryEndpointResult, error) {
	return DiscoveryEndpointResult{}, errors.New("discovery unavailable")
}
func (failingDiscoveryProvider) ListScanJobs(context.Context, DiscoveryScanJobQuery) (DiscoveryScanJobResult, error) {
	return DiscoveryScanJobResult{}, errors.New("discovery unavailable")
}
func (failingDiscoveryProvider) CreateScan(context.Context, string, string, []int) (DiscoveryScanCreateResult, error) {
	return DiscoveryScanCreateResult{}, errors.New("discovery unavailable")
}
func (failingDiscoveryProvider) CancelScanJob(context.Context, string, string) (DiscoveryScanJobActionResult, error) {
	return DiscoveryScanJobActionResult{}, errors.New("discovery unavailable")
}
func (failingDiscoveryProvider) RequeueScanJob(context.Context, string, string) (DiscoveryScanJobActionResult, error) {
	return DiscoveryScanJobActionResult{}, errors.New("discovery unavailable")
}

type failingNotificationProvider struct{}

func (failingNotificationProvider) Delivers() bool { return true }
func (failingNotificationProvider) Name() string   { return "failing" }

func (failingNotificationProvider) GetSummary(context.Context) (NotificationSummary, error) {
	return NotificationSummary{}, errors.New("notification unavailable")
}
func (failingNotificationProvider) ListDeliveries(context.Context, NotificationDeliveryQuery) (NotificationDeliveryResult, error) {
	return NotificationDeliveryResult{}, errors.New("notification unavailable")
}
func (failingNotificationProvider) AckDelivery(context.Context, string, string) (NotificationDeliveryActionResult, error) {
	return NotificationDeliveryActionResult{}, errors.New("notification unavailable")
}
func (failingNotificationProvider) RetryDelivery(context.Context, string, string) (NotificationDeliveryActionResult, error) {
	return NotificationDeliveryActionResult{}, errors.New("notification unavailable")
}
func (failingNotificationProvider) TestDelivery(context.Context, string, string, string) (NotificationTestDeliveryResult, error) {
	return NotificationTestDeliveryResult{}, errors.New("notification unavailable")
}
func (failingNotificationProvider) ListRules(context.Context) ([]NotificationRule, error) {
	return nil, errors.New("notification unavailable")
}
func (failingNotificationProvider) CreateRule(context.Context, string, int, string, string) (NotificationRule, error) {
	return NotificationRule{}, errors.New("notification unavailable")
}
func (failingNotificationProvider) UpdateRule(context.Context, string, bool, string) (NotificationRule, error) {
	return NotificationRule{}, errors.New("notification unavailable")
}
func (failingNotificationProvider) DeleteRule(context.Context, string) error {
	return errors.New("notification unavailable")
}

type failingDashboardActionProvider struct{}

func (failingDashboardActionProvider) ListHistory(context.Context, DashboardActionHistoryQuery) (DashboardActionHistoryResult, error) {
	return DashboardActionHistoryResult{}, errors.New("dashboard actions unavailable")
}
func (failingDashboardActionProvider) AckAction(context.Context, string, string) (DashboardActionAckResult, error) {
	return DashboardActionAckResult{}, errors.New("dashboard actions unavailable")
}
func (failingDashboardActionProvider) ResolveAction(context.Context, string, string) (DashboardActionResolveResult, error) {
	return DashboardActionResolveResult{}, errors.New("dashboard actions unavailable")
}

type stubDiscoveryProvider struct {
	summary DiscoverySummary
}

func (s stubDiscoveryProvider) GetSummary(context.Context) (DiscoverySummary, error) {
	return s.summary, nil
}
func (s stubDiscoveryProvider) ListEndpoints(context.Context, DiscoveryEndpointQuery) (DiscoveryEndpointResult, error) {
	return DiscoveryEndpointResult{}, nil
}
func (s stubDiscoveryProvider) ListScanJobs(context.Context, DiscoveryScanJobQuery) (DiscoveryScanJobResult, error) {
	return DiscoveryScanJobResult{}, nil
}
func (s stubDiscoveryProvider) CreateScan(context.Context, string, string, []int) (DiscoveryScanCreateResult, error) {
	return DiscoveryScanCreateResult{}, nil
}
func (s stubDiscoveryProvider) CancelScanJob(context.Context, string, string) (DiscoveryScanJobActionResult, error) {
	return DiscoveryScanJobActionResult{}, nil
}
func (s stubDiscoveryProvider) RequeueScanJob(context.Context, string, string) (DiscoveryScanJobActionResult, error) {
	return DiscoveryScanJobActionResult{}, nil
}

type stubNotificationProvider struct {
	summary NotificationSummary
}

func (s stubNotificationProvider) Delivers() bool { return true }
func (s stubNotificationProvider) Name() string   { return "stub" }
func (s stubNotificationProvider) GetSummary(context.Context) (NotificationSummary, error) {
	return s.summary, nil
}
func (s stubNotificationProvider) ListDeliveries(context.Context, NotificationDeliveryQuery) (NotificationDeliveryResult, error) {
	return NotificationDeliveryResult{}, nil
}
func (s stubNotificationProvider) AckDelivery(context.Context, string, string) (NotificationDeliveryActionResult, error) {
	return NotificationDeliveryActionResult{}, nil
}
func (s stubNotificationProvider) RetryDelivery(context.Context, string, string) (NotificationDeliveryActionResult, error) {
	return NotificationDeliveryActionResult{}, nil
}
func (s stubNotificationProvider) TestDelivery(context.Context, string, string, string) (NotificationTestDeliveryResult, error) {
	return NotificationTestDeliveryResult{}, nil
}
func (s stubNotificationProvider) ListRules(context.Context) ([]NotificationRule, error) {
	return nil, nil
}
func (s stubNotificationProvider) CreateRule(context.Context, string, int, string, string) (NotificationRule, error) {
	return NotificationRule{}, nil
}
func (s stubNotificationProvider) UpdateRule(context.Context, string, bool, string) (NotificationRule, error) {
	return NotificationRule{}, nil
}
func (s stubNotificationProvider) DeleteRule(context.Context, string) error {
	return nil
}

type stubDashboardActionProvider struct {
	history []DashboardActionHistoryRecord
}

func (s stubDashboardActionProvider) ListHistory(context.Context, DashboardActionHistoryQuery) (DashboardActionHistoryResult, error) {
	return DashboardActionHistoryResult{History: s.history, Total: len(s.history), Limit: 25}, nil
}
func (s stubDashboardActionProvider) AckAction(context.Context, string, string) (DashboardActionAckResult, error) {
	return DashboardActionAckResult{}, nil
}
func (s stubDashboardActionProvider) ResolveAction(context.Context, string, string) (DashboardActionResolveResult, error) {
	return DashboardActionResolveResult{}, nil
}

func TestDashboardSummaryReturns503WhenSourceUnavailable(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	RegisterHandlers(mux, auth, failingCertSummaryProvider{}, stubAuditProvider{}, stubCAProvider{}, stubTemplateProvider{}, NewFileCertificateProviderFromEnv(), NewProtocolProviderFromEnv(), failingDiscoveryProvider{}, failingNotificationProvider{}, failingDashboardActionProvider{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/summary", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 from summary failure, got %d", rec.Code)
	}
}

func TestDashboardActionsReturnRankedItems(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	RegisterHandlers(mux, auth, stubCertSummaryProvider{snapshot: CertSummarySnapshot{Total: 12, Expiring30Days: 4, Expired: 2, Source: "file-store"}}, stubAuditProvider{}, stubCAProvider{}, stubTemplateProvider{}, NewFileCertificateProviderFromEnv(), NewProtocolProviderFromEnv(), stubDiscoveryProvider{summary: DiscoverySummary{DiscoveredEndpoints: 20, RiskyEndpoints: 5, ActiveScanJobs: 1}}, stubNotificationProvider{summary: NotificationSummary{PendingNotifications: 3, OwnershipEscalations: 1, DeliveryFailures24h: 2}}, stubDashboardActionProvider{history: []DashboardActionHistoryRecord{}}, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/actions", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from actions, got %d (%s)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"Replace expired certificates", "Review expiring certificates", "Investigate risky endpoints", "Review notification delivery failures"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected action rail item %q in response: %s", want, body)
		}
	}
}

func TestDashboardActionHistoryReturns503WhenStoreUnavailable(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	RegisterHandlers(mux, auth, stubCertSummaryProvider{snapshot: CertSummarySnapshot{Total: 0, Source: "file-store"}}, stubAuditProvider{}, stubCAProvider{}, stubTemplateProvider{}, NewFileCertificateProviderFromEnv(), NewProtocolProviderFromEnv(), stubDiscoveryProvider{summary: DiscoverySummary{}}, stubNotificationProvider{summary: NotificationSummary{}}, failingDashboardActionProvider{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/actions/history?limit=5", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 from actions history failure, got %d", rec.Code)
	}
}

func TestRegisterHandlersPanicsOnNilDependencies(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected RegisterHandlers to panic when required deps are nil")
		}
	}()

	RegisterHandlers(http.NewServeMux(), nil, stubCertSummaryProvider{snapshot: CertSummarySnapshot{}}, stubAuditProvider{}, stubCAProvider{}, stubTemplateProvider{}, NewFileCertificateProviderFromEnv(), NewProtocolProviderFromEnv(), stubDiscoveryProvider{summary: DiscoverySummary{}}, stubNotificationProvider{summary: NotificationSummary{}}, stubDashboardActionProvider{history: nil}, nil)
}
