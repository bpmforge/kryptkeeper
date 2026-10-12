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

// TestDiscoverySummaryCarriesFindingFunnel is the W2-11 regression for
// acceptance criterion 4: GET /api/v1/discovery/summary built a bespoke
// anonymous response struct that never copied DiscoverySummary.Findings
// onto the wire, so a caller of the live API could not see raw/effective/
// suppressed even after dbDiscoveryProvider.GetSummary computed them. This
// asserts the counts round-trip through the actual HTTP response body, not
// just the provider return value.
func TestDiscoverySummaryCarriesFindingFunnel(t *testing.T) {
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
			MappedCertificates:  15,
			RiskyEndpoints:      5,
			ActiveScanJobs:      1,
			Findings:            FindingFunnelSummary{Raw: 9, Effective: 6, Suppressed: 3},
		}},
		stubNotificationProvider{}, stubDashboardActionProvider{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/discovery/summary", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rec.Code, rec.Body.String())
	}

	var body struct {
		Data struct {
			Findings FindingFunnelSummary `json:"findings"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	want := FindingFunnelSummary{Raw: 9, Effective: 6, Suppressed: 3}
	if body.Data.Findings != want {
		t.Fatalf("expected findings %+v on the wire, got %+v (body: %s)", want, body.Data.Findings, rec.Body.String())
	}
}

// TestDiscoverySummaryReturns503WhenSourceUnavailable mirrors the dashboard
// equivalent: a provider failure must fail closed, not fall back to a
// zero-valued (and therefore misleadingly "clean") finding funnel.
func TestDiscoverySummaryReturns503WhenSourceUnavailable(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	RegisterHandlers(mux, auth,
		stubCertSummaryProvider{snapshot: CertSummarySnapshot{Total: 0, Source: "file-store"}},
		stubAuditProvider{}, stubCAProvider{}, stubTemplateProvider{},
		NewFileCertificateProviderFromEnv(), NewProtocolProviderFromEnv(),
		failingDiscoveryProvider{}, stubNotificationProvider{}, stubDashboardActionProvider{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/discovery/summary", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 from discovery summary failure, got %d", rec.Code)
	}
}

// discoveryEventTestProvider is a DiscoveryProvider stub whose write results
// (CreateScan/CancelScanJob/RequeueScanJob) are set directly by the test, so
// W8-14's SSE-producer tests below can assert the exact op_id/status that
// reaches the event bus, not just that some call succeeded.
type discoveryEventTestProvider struct {
	createResult  DiscoveryScanCreateResult
	cancelResult  DiscoveryScanJobActionResult
	requeueResult DiscoveryScanJobActionResult
}

func (p discoveryEventTestProvider) GetSummary(context.Context) (DiscoverySummary, error) {
	return DiscoverySummary{}, nil
}
func (p discoveryEventTestProvider) ListEndpoints(context.Context, DiscoveryEndpointQuery) (DiscoveryEndpointResult, error) {
	return DiscoveryEndpointResult{}, nil
}
func (p discoveryEventTestProvider) ListScanJobs(context.Context, DiscoveryScanJobQuery) (DiscoveryScanJobResult, error) {
	return DiscoveryScanJobResult{}, nil
}
func (p discoveryEventTestProvider) CreateScan(context.Context, string, string, []int) (DiscoveryScanCreateResult, error) {
	return p.createResult, nil
}
func (p discoveryEventTestProvider) CancelScanJob(context.Context, string, string) (DiscoveryScanJobActionResult, error) {
	return p.cancelResult, nil
}
func (p discoveryEventTestProvider) RequeueScanJob(context.Context, string, string) (DiscoveryScanJobActionResult, error) {
	return p.requeueResult, nil
}

// TestDiscoveryScanCreate_SucceedsWithNoSSESubscriber is the acceptance #8
// regression: starting a scan must succeed even when nobody is listening on
// the event bus, and must not hang trying to deliver the event.
func TestDiscoveryScanCreate_SucceedsWithNoSSESubscriber(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	auth := NewAuthenticatorFromEnv()

	bus := NewEventBus(3) // nobody ever subscribes
	mux := http.NewServeMux()
	registerDiscoveryHandlers(mux, auth, discoveryEventTestProvider{
		createResult: DiscoveryScanCreateResult{ID: "scan-1", Status: "queued", ScanType: "full", Target: "10.0.0.0/24", QueuedAt: "2026-07-29T00:00:00Z"},
	}, bus, stubAuditProvider{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/discovery/scans", strings.NewReader(`{"scan_type":"full","target":"10.0.0.0/24"}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		mux.ServeHTTP(rec, req)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("scan creation hung with no SSE subscriber attached -- Publish must be non-blocking")
	}
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d (%s)", rec.Code, rec.Body.String())
	}
}

// TestDiscoveryScanCreate_PublishesEventDeliveredToAnyInTenantPrincipal is
// the acceptance #3 regression: op_id correlation needs no new lookup (the
// event's op_id is exactly the ID the create call already returned), and the
// event reaches a DIFFERENT principal in the same tenant who never started
// the scan -- delivery is tenant-scoped, not scoped to the caller.
func TestDiscoveryScanCreate_PublishesEventDeliveredToAnyInTenantPrincipal(t *testing.T) {
	t.Setenv("MULTI_TENANCY", "on")
	auth := newRateLimitTestAuth(t)
	creatorToken := newSSETestAPIKey(t, auth, "scan-creator", "discovery-operator", "acme")
	watcherToken := newSSETestAPIKey(t, auth, "scan-watcher", "pki-operator", "acme")

	bus := NewEventBus(3)
	mux := http.NewServeMux()
	registerDiscoveryHandlers(mux, auth, discoveryEventTestProvider{
		createResult: DiscoveryScanCreateResult{ID: "scan-abc123", Status: "queued", ScanType: "full", Target: "10.0.0.0/24", QueuedAt: "2026-07-29T00:00:00Z"},
	}, bus, stubAuditProvider{})
	registerSSEHandlers(mux, auth, bus, stubAuditProvider{}, testSSEConfig())
	srv := httptest.NewServer(mux)
	defer srv.Close()

	watcher := connectSSE(t, srv.URL, watcherToken, "acme")
	defer watcher.close()

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/discovery/scans", strings.NewReader(`{"scan_type":"full","target":"10.0.0.0/24"}`))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+creatorToken)
	req.Header.Set("X-Tenant", "acme")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 creating scan, got %d", resp.StatusCode)
	}

	evt, ok := watcher.nextEvent(t, 2*time.Second)
	if !ok {
		t.Fatal("expected the watcher (who never started the scan) to receive an event, got none")
	}
	if evt.OpID != "scan-abc123" {
		t.Fatalf("expected op_id scan-abc123 (the id the create call returned), got %q", evt.OpID)
	}
	if evt.Kind != EventKindScan || evt.Status != "queued" {
		t.Fatalf("expected kind=scan status=queued, got kind=%q status=%q", evt.Kind, evt.Status)
	}
}

// TestDiscoveryScanJobCancel_PublishesNormalizedCancelledStatus is a gate-
// failure regression: every CancelScanJob implementation
// (discovery_db_provider.go, discovery_scanner_provider.go,
// discovery_file_provider.go) reports a successful cancel as "canceled"
// (single L), not the "cancelled" (double L) docs/openapi.yaml's
// DiscoveryScanJob and OperationEvent schemas declare. Before
// normalizeScanJobEventStatus existed, that non-enum spelling reached
// subscribers verbatim. Red-checked by temporarily publishing result.Status
// unnormalized: this test failed with status="canceled"; restored.
func TestDiscoveryScanJobCancel_PublishesNormalizedCancelledStatus(t *testing.T) {
	t.Setenv("MULTI_TENANCY", "on")
	auth := newRateLimitTestAuth(t)
	callerToken := newSSETestAPIKey(t, auth, "canceller", "discovery-operator", "acme")

	bus := NewEventBus(3)
	mux := http.NewServeMux()
	registerDiscoveryHandlers(mux, auth, discoveryEventTestProvider{
		cancelResult: DiscoveryScanJobActionResult{ScanJobID: "scan-xyz", Status: "canceled", Reason: "operator request", UpdatedAt: "2026-07-29T00:00:00Z"},
	}, bus, stubAuditProvider{})
	registerSSEHandlers(mux, auth, bus, stubAuditProvider{}, testSSEConfig())
	srv := httptest.NewServer(mux)
	defer srv.Close()

	watcher := connectSSE(t, srv.URL, callerToken, "acme")
	defer watcher.close()

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/discovery/scan-jobs/cancel", strings.NewReader(`{"scan_job_id":"scan-xyz"}`))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+callerToken)
	req.Header.Set("X-Tenant", "acme")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("cancel scan job: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202 cancelling scan job, got %d", resp.StatusCode)
	}

	evt, ok := watcher.nextEvent(t, 2*time.Second)
	if !ok {
		t.Fatal("expected a cancel event, got none")
	}
	if evt.Status != "cancelled" {
		t.Fatalf("expected normalized status %q (OperationEvent enum), got %q", "cancelled", evt.Status)
	}
}

// TestDiscoveryScanJobCancel_NotFoundDoesNotPublishBogusStatus is the other
// half of the gate-failure regression: when the target job is already
// terminal or missing, CancelScanJob returns a nil error with a
// non-terminal sentinel status ("not_found_or_already_terminal" for the db
// providers, "not_found" for the scanner provider) rather than a real state
// transition. Publishing that sentinel would put a value outside
// OperationEvent's documented enum on the wire; normalizeScanJobEventStatus
// must reject it instead, so no event is delivered at all.
func TestDiscoveryScanJobCancel_NotFoundDoesNotPublishBogusStatus(t *testing.T) {
	t.Setenv("MULTI_TENANCY", "on")
	auth := newRateLimitTestAuth(t)
	callerToken := newSSETestAPIKey(t, auth, "canceller", "discovery-operator", "acme")

	bus := NewEventBus(3)
	mux := http.NewServeMux()
	registerDiscoveryHandlers(mux, auth, discoveryEventTestProvider{
		cancelResult: DiscoveryScanJobActionResult{ScanJobID: "scan-xyz", Status: "not_found_or_already_terminal"},
	}, bus, stubAuditProvider{})
	registerSSEHandlers(mux, auth, bus, stubAuditProvider{}, testSSEConfig())
	srv := httptest.NewServer(mux)
	defer srv.Close()

	watcher := connectSSE(t, srv.URL, callerToken, "acme")
	defer watcher.close()

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/discovery/scan-jobs/cancel", strings.NewReader(`{"scan_job_id":"scan-xyz"}`))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+callerToken)
	req.Header.Set("X-Tenant", "acme")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("cancel scan job: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202 (CancelScanJob returns nil error for a not-found/terminal job), got %d", resp.StatusCode)
	}

	watcher.expectNoEvent(t, 500*time.Millisecond)
}

// TestDiscoveryScanJobRequeue_PublishesCanonicalQueuedStatus covers the
// requeue producer's status guard named alongside cancel's in the gate
// failure. RequeueScanJob returns "queued" (already canonical) on every
// provider's success path today, so normalizeScanJobEventStatus can never
// reject it there -- but the guard is on that call site too, and this pins
// the requeue producer's published event so a future provider change that
// stops returning a canonical status is caught here rather than shipping
// unnoticed, matching cancel's coverage.
func TestDiscoveryScanJobRequeue_PublishesCanonicalQueuedStatus(t *testing.T) {
	t.Setenv("MULTI_TENANCY", "on")
	auth := newRateLimitTestAuth(t)
	callerToken := newSSETestAPIKey(t, auth, "requeuer", "discovery-operator", "acme")

	bus := NewEventBus(3)
	mux := http.NewServeMux()
	registerDiscoveryHandlers(mux, auth, discoveryEventTestProvider{
		requeueResult: DiscoveryScanJobActionResult{PreviousID: "scan-old", ScanJobID: "scan-new", Status: "queued", Reason: "retry", QueuedAt: "2026-07-29T00:00:00Z"},
	}, bus, stubAuditProvider{})
	registerSSEHandlers(mux, auth, bus, stubAuditProvider{}, testSSEConfig())
	srv := httptest.NewServer(mux)
	defer srv.Close()

	watcher := connectSSE(t, srv.URL, callerToken, "acme")
	defer watcher.close()

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/discovery/scan-jobs/requeue", strings.NewReader(`{"scan_job_id":"scan-old"}`))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+callerToken)
	req.Header.Set("X-Tenant", "acme")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("requeue scan job: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202 requeuing scan job, got %d", resp.StatusCode)
	}

	evt, ok := watcher.nextEvent(t, 2*time.Second)
	if !ok {
		t.Fatal("expected a requeue event, got none")
	}
	if evt.OpID != "scan-new" || evt.Status != "queued" {
		t.Fatalf("expected op_id=scan-new status=queued, got op_id=%q status=%q", evt.OpID, evt.Status)
	}
}

// TestDiscoveryScanCreate_AcceptsK8sCertManagerScanType is the W19-17
// regression: handlers_discovery.go's scan_type switch had no case for
// k8s-certmanager at all, so both discovery providers' CreateScan (which
// already ran a real cert-manager scan) were unreachable via the API —
// every request 400'd before either provider was even called.
func TestDiscoveryScanCreate_AcceptsK8sCertManagerScanType(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	auth := NewAuthenticatorFromEnv()

	bus := NewEventBus(3)
	mux := http.NewServeMux()
	registerDiscoveryHandlers(mux, auth, discoveryEventTestProvider{
		createResult: DiscoveryScanCreateResult{ID: "scan-k8s-1", Status: "running", ScanType: scanTypeK8sCertManager, QueuedAt: "2026-09-10T00:00:00Z"},
	}, bus, stubAuditProvider{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/discovery/scans", strings.NewReader(`{"scan_type":"k8s-certmanager"}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 accepting k8s-certmanager, got %d (%s)", rec.Code, rec.Body.String())
	}
}

// TestDiscoveryScanCreate_K8sCertManagerRejectsTarget: like the cloud scan
// types, k8s-certmanager's scope is the connector's own credentials —
// a caller-supplied target is meaningless and must be rejected, not
// silently ignored.
func TestDiscoveryScanCreate_K8sCertManagerRejectsTarget(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	auth := NewAuthenticatorFromEnv()

	bus := NewEventBus(3)
	mux := http.NewServeMux()
	registerDiscoveryHandlers(mux, auth, discoveryEventTestProvider{}, bus, stubAuditProvider{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/discovery/scans", strings.NewReader(`{"scan_type":"k8s-certmanager","target":"cluster"}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 rejecting a target for k8s-certmanager, got %d (%s)", rec.Code, rec.Body.String())
	}
}
