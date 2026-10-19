// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"testing"
)

func TestFileProtocolProviderGetStatus(t *testing.T) {
	t.Setenv("APP_PROTOCOL_ACME_ENABLED", "true")
	t.Setenv("APP_PROTOCOL_EST_ENABLED", "false")
	t.Setenv("APP_PROTOCOL_CRL_ENABLED", "1")

	p := newFileProtocolProvider()
	status, err := p.GetStatus(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !status.ACME {
		t.Error("expected ACME enabled")
	}
	if status.EST {
		t.Error("expected EST disabled")
	}
	if !status.CRL {
		t.Error("expected CRL enabled")
	}
	if status.SCEP {
		t.Error("expected SCEP disabled by default")
	}
}

func TestFileProtocolProviderGetReadiness(t *testing.T) {
	t.Setenv("APP_PROTOCOL_ACME_ENABLED", "true")
	t.Setenv("APP_PROTOCOL_ACME_HEALTHY", "true")
	t.Setenv("APP_PROTOCOL_EST_ENABLED", "true")
	t.Setenv("APP_PROTOCOL_EST_HEALTHY", "false")

	p := newFileProtocolProvider()
	readiness, err := p.GetReadiness(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !readiness.ACME.Enabled || !readiness.ACME.Healthy {
		t.Error("expected ACME enabled+healthy")
	}
	if !readiness.EST.Enabled || readiness.EST.Healthy {
		t.Error("expected EST enabled but unhealthy")
	}
	if readiness.SCEP.Enabled || readiness.SCEP.Healthy {
		t.Error("expected SCEP disabled+unhealthy")
	}
}

func TestFileProtocolProviderGetConformance(t *testing.T) {
	t.Setenv("APP_PROTOCOL_ACME_CONFORMANCE_STATE", "warn")
	t.Setenv("APP_PROTOCOL_ACME_CONFORMANCE_RATE", "85")

	p := newFileProtocolProvider()
	conformance, err := p.GetConformance(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conformance.ACME.State != "warn" {
		t.Errorf("expected ACME state warn, got %q", conformance.ACME.State)
	}
	if conformance.ACME.PassingRate != 85 {
		t.Errorf("expected ACME rate 85, got %d", conformance.ACME.PassingRate)
	}
	if conformance.EST.State != "pass" {
		t.Errorf("expected EST default state pass, got %q", conformance.EST.State)
	}
	if conformance.EST.PassingRate != 100 {
		t.Errorf("expected EST default rate 100, got %d", conformance.EST.PassingRate)
	}
}

func TestFileProtocolProviderTriggerRecheck(t *testing.T) {
	p := newFileProtocolProvider()
	result, err := p.TriggerConformanceRecheck(context.Background(), "acme", "test run")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Suite != "acme" {
		t.Errorf("expected suite acme, got %q", result.Suite)
	}
	if result.Status != "queued" {
		t.Errorf("expected status queued, got %q", result.Status)
	}
	if result.JobID == "" {
		t.Error("expected non-empty job ID")
	}
}

func TestFileDiscoveryProviderGetSummary(t *testing.T) {
	t.Setenv("APP_DISCOVERY_DISCOVERED_ENDPOINTS", "42")
	t.Setenv("APP_DISCOVERY_RISKY_ENDPOINTS", "3")

	p := newFileDiscoveryProvider()
	summary, err := p.GetSummary(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if summary.DiscoveredEndpoints != 42 {
		t.Errorf("expected 42 endpoints, got %d", summary.DiscoveredEndpoints)
	}
	if summary.RiskyEndpoints != 3 {
		t.Errorf("expected 3 risky, got %d", summary.RiskyEndpoints)
	}
}

func TestFileDiscoveryProviderListEndpoints(t *testing.T) {
	t.Setenv(discoveryDemoSeedsEnv, "true") // S-70: seeds are opt-in
	p := newFileDiscoveryProvider()

	result, err := p.ListEndpoints(context.Background(), DiscoveryEndpointQuery{Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Total != 3 {
		t.Errorf("expected 3 total endpoints, got %d", result.Total)
	}

	// filter by risky only
	result, err = p.ListEndpoints(context.Background(), DiscoveryEndpointQuery{RiskyOnly: true, Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Total != 1 {
		t.Errorf("expected 1 risky endpoint, got %d", result.Total)
	}

	// filter by protocol
	result, err = p.ListEndpoints(context.Background(), DiscoveryEndpointQuery{Protocol: "http", Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Total != 1 {
		t.Errorf("expected 1 http endpoint, got %d", result.Total)
	}
}

func TestFileDiscoveryProviderListScanJobs(t *testing.T) {
	t.Setenv(discoveryDemoSeedsEnv, "true") // S-70: seeds are opt-in
	p := newFileDiscoveryProvider()

	result, err := p.ListScanJobs(context.Background(), DiscoveryScanJobQuery{Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Total != 3 {
		t.Errorf("expected 3 total scan jobs, got %d", result.Total)
	}

	// filter by status
	result, err = p.ListScanJobs(context.Background(), DiscoveryScanJobQuery{Status: "running", Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Total != 1 {
		t.Errorf("expected 1 running scan job, got %d", result.Total)
	}
}

func TestFileDiscoveryProviderCreateScanRefuses(t *testing.T) {
	// The file provider has no scan runner. It used to fabricate a
	// "queued" job it then discarded — the user's first scan vanished
	// behind a success response. It must refuse instead.
	p := newFileDiscoveryProvider()
	if _, err := p.CreateScan(context.Background(), "full", "10.0.0.0/24", nil); !errors.Is(err, errDiscoveryScanUnsupported) {
		t.Fatalf("expected errDiscoveryScanUnsupported, got %v", err)
	}
}

func TestFileDiscoveryProviderCancelScanJobRefuses(t *testing.T) {
	p := newFileDiscoveryProvider()
	if _, err := p.CancelScanJob(context.Background(), "scan-123", "test cancel"); !errors.Is(err, errDiscoveryScanUnsupported) {
		t.Fatalf("expected errDiscoveryScanUnsupported, got %v", err)
	}
}

func TestFileNotificationProviderGetSummary(t *testing.T) {
	t.Setenv("APP_NOTIFICATIONS_PENDING", "5")
	t.Setenv("APP_NOTIFICATIONS_ESCALATIONS", "2")

	p := newFileNotificationProvider()
	summary, err := p.GetSummary(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if summary.PendingNotifications != 5 {
		t.Errorf("expected 5 pending, got %d", summary.PendingNotifications)
	}
	if summary.OwnershipEscalations != 2 {
		t.Errorf("expected 2 escalations, got %d", summary.OwnershipEscalations)
	}
}

func TestFileNotificationProviderListDeliveries(t *testing.T) {
	p := newFileNotificationProvider()

	// unfiltered: full seeded set comes back
	result, err := p.ListDeliveries(context.Background(), NotificationDeliveryQuery{Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Total != 3 {
		t.Errorf("expected 3 seeded deliveries, got %d", result.Total)
	}

	// filter by status+channel: smoke suite depends on this exact fixture id
	result, err = p.ListDeliveries(context.Background(), NotificationDeliveryQuery{Status: "failed", Channel: "email", Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Total != 1 {
		t.Errorf("expected 1 failed+email delivery, got %d", result.Total)
	}
	if len(result.Deliveries) != 1 || result.Deliveries[0].ID != "notif-failed-1" {
		t.Errorf("expected delivery notif-failed-1, got %+v", result.Deliveries)
	}

	// filter by channel only
	result, err = p.ListDeliveries(context.Background(), NotificationDeliveryQuery{Channel: "slack", Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Total != 1 {
		t.Errorf("expected 1 slack delivery, got %d", result.Total)
	}
}

func TestFileNotificationProviderAckDelivery(t *testing.T) {
	p := newFileNotificationProvider()
	result, err := p.AckDelivery(context.Background(), "notif-1", "test ack")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "acknowledged" {
		t.Errorf("expected acknowledged, got %q", result.Status)
	}
}

func TestFileNotificationProviderTestDelivery(t *testing.T) {
	p := newFileNotificationProvider()
	result, err := p.TestDelivery(context.Background(), "slack", "#test", "hello")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "queued" {
		t.Errorf("expected queued, got %q", result.Status)
	}
	if result.Channel != "slack" {
		t.Errorf("expected slack channel, got %q", result.Channel)
	}
}

// UI finding 6: a real hub must not serve the canned sample rows.
func TestFileDashboardActionProviderServesNoFixtureByDefault(t *testing.T) {
	t.Setenv(dashboardActionDemoEnv, "")
	result, err := newFileDashboardActionProvider().ListHistory(context.Background(), DashboardActionHistoryQuery{Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Total != 0 || len(result.History) != 0 {
		t.Fatalf("default history must be empty, got %+v", result.History)
	}
}

func TestFileDashboardActionProviderListHistory(t *testing.T) {
	t.Setenv(dashboardActionDemoEnv, "true")
	p := newFileDashboardActionProvider()

	result, err := p.ListHistory(context.Background(), DashboardActionHistoryQuery{Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Total != 3 {
		t.Errorf("expected 3 history records, got %d", result.Total)
	}

	// filter by status
	result, err = p.ListHistory(context.Background(), DashboardActionHistoryQuery{Status: "open", Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Total != 1 {
		t.Errorf("expected 1 open record, got %d", result.Total)
	}
}

func TestFileDashboardActionProviderAckAction(t *testing.T) {
	p := newFileDashboardActionProvider()
	result, err := p.AckAction(context.Background(), "act-1", "test ack")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "acknowledged" {
		t.Errorf("expected acknowledged, got %q", result.Status)
	}
	if result.ActionID != "act-1" {
		t.Errorf("expected act-1, got %q", result.ActionID)
	}
}

func TestFileDashboardActionProviderResolveAction(t *testing.T) {
	p := newFileDashboardActionProvider()
	result, err := p.ResolveAction(context.Background(), "act-2", "fixed")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "resolved" {
		t.Errorf("expected resolved, got %q", result.Status)
	}
	if result.ResolvedAt == "" {
		t.Error("expected non-empty resolved_at")
	}
}

func TestPaginateHelper(t *testing.T) {
	items := []int{1, 2, 3, 4, 5}

	// first page
	r := paginate(items, 2, 0, 10, 100)
	if r.Total != 5 || len(r.Items) != 2 || r.Items[0] != 1 {
		t.Errorf("first page: total=%d items=%v", r.Total, r.Items)
	}
	if r.NextCursor == nil || *r.NextCursor != 2 {
		t.Error("expected next_cursor=2")
	}
	if r.PrevCursor != nil {
		t.Error("expected no prev_cursor on first page")
	}

	// second page
	r = paginate(items, 2, 2, 10, 100)
	if len(r.Items) != 2 || r.Items[0] != 3 {
		t.Errorf("second page: items=%v", r.Items)
	}
	if r.PrevCursor == nil || *r.PrevCursor != 0 {
		t.Error("expected prev_cursor=0")
	}

	// last page
	r = paginate(items, 2, 4, 10, 100)
	if len(r.Items) != 1 || r.Items[0] != 5 {
		t.Errorf("last page: items=%v", r.Items)
	}
	if r.NextCursor != nil {
		t.Error("expected no next_cursor on last page")
	}
}
