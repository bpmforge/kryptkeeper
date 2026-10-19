// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/agentinstall"
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

// W24-04: GET/PUT /api/v1/discovery/schedules.

type scheduleHarness struct {
	mux      *http.ServeMux
	auth     *Authenticator
	rec      *recordingDiscoveryProvider
	store    *memoryDiscoveryScheduleStore
	targetID string
	audit    *scepRecordingAudit
}

func newScheduleHarness(t *testing.T) *scheduleHarness {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("KRYPTKEEPER_DISCOVERY_SCAN_TARGETS", "10.0.0.0/24")
	t.Setenv("KRYPTKEEPER_DISCOVERY_SCAN_INTERVAL", "12h")
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32-chars-minimum!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	targets, _ := winrmTestStores(t)
	created, err := targets.Create(context.Background(), ManagedTarget{
		Name: "win-1", Host: "win1.example.com", DiscoveryMode: "winrm", InstallMode: "agent", RenewalMethod: "manual", Tenant: "default",
	})
	if err != nil {
		t.Fatalf("create target: %v", err)
	}
	h := &scheduleHarness{
		mux: http.NewServeMux(), auth: NewAuthenticatorFromEnv(), rec: &recordingDiscoveryProvider{},
		store: newMemoryDiscoveryScheduleStore(), targetID: created.ID, audit: &scepRecordingAudit{},
	}
	registerDiscoveryScheduleHandlers(h.mux, h.auth, h.rec, h.store, targets, h.audit)
	return h
}

func (h *scheduleHarness) do(method, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/api/v1/discovery/schedules", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	return rec
}

func decodeScheduleRows(t *testing.T, rec *httptest.ResponseRecorder) []discoveryScheduleRow {
	t.Helper()
	var body struct {
		Data []discoveryScheduleRow `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	return body.Data
}

func findScheduleRow(rows []discoveryScheduleRow, key string) *discoveryScheduleRow {
	for i := range rows {
		if rows[i].Key == key {
			return &rows[i]
		}
	}
	return nil
}

func TestDiscoverySchedulesHandler_ListShowsLastAndNextRun(t *testing.T) {
	h := newScheduleHarness(t)
	ran := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	_ = h.store.RecordRun(context.Background(), "10.0.0.0/24", "targeted", "10.0.0.0/24", "job-1", ran)

	rec := h.do(http.MethodGet, "test-token", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	rows := decodeScheduleRows(t, rec)
	env := findScheduleRow(rows, "10.0.0.0/24")
	if env == nil || env.Source != "env" || env.LastRun == nil || *env.LastRun != ran.Format(time.RFC3339) {
		t.Fatalf("env row: %+v", env)
	}
	wantNext := ran.Add(12 * time.Hour).Format(time.RFC3339)
	if env.NextRun == nil || *env.NextRun != wantNext || env.IntervalSeconds != nil ||
		env.EffectiveIntervalSeconds == nil || *env.EffectiveIntervalSeconds != 43200 {
		t.Fatalf("env next/interval: %+v", env)
	}
	managed := findScheduleRow(rows, h.targetID)
	if managed == nil || managed.Source != "managed" || managed.ScanType != scanTypeWinRM || managed.Name != "win-1" || managed.LastRun != nil || managed.NextRun == nil {
		t.Fatalf("managed row (never run => last_run null, next_run now): %+v", managed)
	}
}

func TestDiscoverySchedulesHandler_PutSetsAndClears(t *testing.T) {
	h := newScheduleHarness(t)
	rec := h.do(http.MethodPut, "test-token", `{"key":"10.0.0.0/24","interval_seconds":3600}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("set: %d %s", rec.Code, rec.Body.String())
	}
	var one struct {
		Data discoveryScheduleRow `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &one)
	if one.Data.IntervalSeconds == nil || *one.Data.IntervalSeconds != 3600 || *one.Data.EffectiveIntervalSeconds != 3600 {
		t.Fatalf("set response: %+v", one.Data)
	}
	if got, _ := h.store.List(context.Background()); got["10.0.0.0/24"].Interval == nil {
		t.Fatal("override not persisted")
	}

	rec = h.do(http.MethodPut, "test-token", `{"key":"10.0.0.0/24","interval_seconds":null}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("clear: %d %s", rec.Code, rec.Body.String())
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &one)
	if one.Data.IntervalSeconds != nil || *one.Data.EffectiveIntervalSeconds != 43200 {
		t.Fatalf("clear response should fall back to global: %+v", one.Data)
	}

	if rec = h.do(http.MethodPut, "test-token", `{"key":"nope","interval_seconds":3600}`); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown key: %d", rec.Code)
	}
}

func TestDiscoverySchedulesHandler_PutRejectsOutOfRange(t *testing.T) {
	h := newScheduleHarness(t)
	for _, v := range []string{"59", "2592001", "0", "-5", `"abc"`} {
		rec := h.do(http.MethodPut, "test-token", `{"key":"10.0.0.0/24","interval_seconds":`+v+`}`)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("interval %s: want 400, got %d", v, rec.Code)
		}
	}
	for _, v := range []string{"60", "2592000"} {
		if rec := h.do(http.MethodPut, "test-token", `{"key":"10.0.0.0/24","interval_seconds":`+v+`}`); rec.Code != http.StatusOK {
			t.Fatalf("boundary %s: want 200, got %d", v, rec.Code)
		}
	}
}

func TestDiscoverySchedulesHandler_PutRequiresManage(t *testing.T) {
	h := newScheduleHarness(t)
	_, key, err := h.auth.CreateAPIKey("auditor", "auditor-svc", "pki-auditor", nil, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if rec := h.do(http.MethodPut, key, `{"key":"10.0.0.0/24","interval_seconds":3600}`); rec.Code != http.StatusForbidden {
		t.Fatalf("read-only PUT: want 403, got %d", rec.Code)
	}
	if rec := h.do(http.MethodGet, key, ""); rec.Code != http.StatusOK {
		t.Fatalf("read-only GET: want 200, got %d", rec.Code)
	}
	if got, _ := h.store.List(context.Background()); len(got) != 0 {
		t.Fatalf("denied PUT must not write: %+v", got)
	}
}

func TestDiscoverySchedulesHandler_RunningRowDoesNotAdvanceNextRun(t *testing.T) {
	h := newScheduleHarness(t)
	ran := time.Now().UTC().Add(-13 * time.Hour).Truncate(time.Second) // overdue
	_ = h.store.RecordRun(context.Background(), "10.0.0.0/24", "targeted", "10.0.0.0/24", "job-1", ran)
	h.rec.setRunning(DiscoveryScanJob{ID: "job-live", ScanType: "targeted", Target: "10.0.0.0/24", Status: "running"})

	row := findScheduleRow(decodeScheduleRows(t, h.do(http.MethodGet, "test-token", "")), "10.0.0.0/24")
	if row == nil || !row.Running || row.RunningJobID != "job-live" {
		t.Fatalf("row should report the running job: %+v", row)
	}
	if want := ran.Add(12 * time.Hour).Format(time.RFC3339); row.NextRun == nil || *row.NextRun != want {
		t.Fatalf("next_run must stay last_run+interval while running, got %v want %s", row.NextRun, want)
	}
}

func TestDiscoverySchedulesHandler_PutAuditsEveryFailure(t *testing.T) {
	for name, body := range map[string]string{
		"malformed json":   `{`,
		"missing key":      `{"interval_seconds":3600}`,
		"missing interval": `{"key":"10.0.0.0/24"}`,
		"out of range":     `{"key":"10.0.0.0/24","interval_seconds":1}`,
		"unknown key":      `{"key":"nope","interval_seconds":3600}`,
	} {
		h := newScheduleHarness(t)
		if rec := h.do(http.MethodPut, "test-token", body); rec.Code < 400 {
			t.Fatalf("%s: want an error status, got %d", name, rec.Code)
		}
		if len(h.audit.entries) != 1 || h.audit.entries[0].Action != "discovery.schedule.update" || h.audit.entries[0].Outcome != AuditOutcomeFailure {
			t.Fatalf("%s: want one failure audit row, got %+v", name, h.audit.entries)
		}
	}
}

// ---- W34-17: just-in-time sudo password ----

func jitScanFixture(t *testing.T, pw string, credMode map[string]string) (post func(body string) *httptest.ResponseRecorder, db *sql.DB, exec *privFakeExec, audit *sshRecordingAudit, done chan struct{}, logs *bytes.Buffer) {
	t.Helper()
	logs = captureLogs(t, slog.LevelDebug)
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32-chars-minimum!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	targets, creds := winrmTestStores(t)
	if _, err := creds.Create(context.Background(), "cred-jit", "kkscan", CredentialTypeSSHKey, "", sshPayloadWithPrivilege(t, credMode)); err != nil {
		t.Fatal(err)
	}
	if _, err := targets.Create(context.Background(), ManagedTarget{ID: "t-jit", Name: "jit", Host: "192.0.2.77", DiscoveryMode: "network",
		InstallMode: "ssh", RenewalMethod: "manual", CredentialRef: "cred-jit"}); err != nil {
		t.Fatal(err)
	}
	exec = newPrivFake(t, pw)
	audit = &sshRecordingAudit{}
	db = setupDiscoveryTestDB(t)
	store := &sqliteDiscoveryStore{db: db}
	store.SetSSHScanner(newSSHTargetScanner(targets, creds, audit, func(context.Context, agentinstall.SSHTarget) (agentinstall.Executor, func() error, error) {
		return exec, func() error { return nil }, nil
	}))
	done = make(chan struct{})
	orig, origTLS := afterDiscoveryScanPersist, auditEndpointTLSIssues
	afterDiscoveryScanPersist = func(string) { close(done) }
	auditEndpointTLSIssues = func(string, int) []string { return nil } // no live TLS dial in a unit test
	t.Cleanup(func() { afterDiscoveryScanPersist, auditEndpointTLSIssues = orig, origTLS })

	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	registerDiscoveryHandlersWithTargets(mux, auth, store, nil, audit, targets)
	_, key, err := auth.CreateAPIKey("adm", "adm", "pki-admin", nil, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	post = func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/discovery/scans", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+key)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w
	}
	return
}

func dumpSQLite(t *testing.T, db *sql.DB) string {
	t.Helper()
	var sb strings.Builder
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table'`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var n string
		_ = rows.Scan(&n)
		tables = append(tables, n)
	}
	rows.Close()
	for _, tbl := range tables {
		r, err := db.Query(`SELECT * FROM "` + tbl + `"`)
		if err != nil {
			continue
		}
		cols, _ := r.Columns()
		for r.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			_ = r.Scan(ptrs...)
			fmt.Fprintln(&sb, tbl, vals)
		}
		r.Close()
	}
	return sb.String()
}

func TestJITSudoPasswordScanIsMemoryOnly(t *testing.T) {
	const pw = "Jit-Sudo-Pw-8842"
	post, db, exec, audit, done, logs := jitScanFixture(t, pw, nil) // credential has no sudo of its own
	w := post(`{"scan_type":"ssh","target":"t-jit","jit_sudo_password":"` + pw + `"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("scan never finished")
	}
	joined := strings.Join(exec.argv, "\n")
	if !strings.Contains(joined, "sudo -S -p  -k -- cat /etc/ssl/certs/root.crt") {
		t.Fatalf("the password must have been used for this run:\n%s", joined)
	}
	if strings.Contains(joined, pw) {
		t.Fatal("password in argv")
	}
	if strings.Contains(w.Body.String(), pw) {
		t.Fatal("password echoed in the response")
	}
	if strings.Contains(dumpSQLite(t, db), pw) {
		t.Fatal("password reached the database")
	}
	if strings.Contains(logs.String(), pw) {
		t.Fatalf("password in logs: %s", logs.String())
	}
	audit.mu.Lock()
	defer audit.mu.Unlock()
	var jit bool
	for _, e := range audit.entries {
		b, _ := json.Marshal(e)
		if strings.Contains(string(b), pw) {
			t.Fatalf("password in audit: %s", b)
		}
		if e.Action == "discovery.scan.create" && strings.Contains(e.ChangeSummary, "privilege_source=jit") {
			jit = true
		}
	}
	if !jit {
		t.Fatalf("audit must record privilege_source=jit: %+v", audit.entries)
	}
}

func TestJITSudoPasswordIsZeroizedAtJobEnd(t *testing.T) {
	const pw = "Zero-Me-5531"
	targets, creds := winrmTestStores(t)
	_, _ = creds.Create(context.Background(), "c", "k", CredentialTypeSSHKey, "", sshPayloadWithPrivilege(t, nil))
	_, _ = targets.Create(context.Background(), ManagedTarget{ID: "t", Name: "t", Host: "192.0.2.1", DiscoveryMode: "network", InstallMode: "ssh", RenewalMethod: "manual", CredentialRef: "c"})
	run := newSSHTargetScanner(targets, creds, &sshRecordingAudit{}, func(context.Context, agentinstall.SSHTarget) (agentinstall.Executor, func() error, error) {
		return newPrivFake(t, pw), func() error { return nil }, nil
	})
	j := newJITSudo(pw)
	run(withJITSudo(context.Background(), j), "t")
	if j.pw != nil {
		t.Fatal("the secret must be wiped when the job ends")
	}
}

func TestJITSudoPasswordValidation(t *testing.T) {
	post, _, exec, _, _, _ := jitScanFixture(t, "x", nil)
	if w := post(`{"scan_type":"full","target":"10.0.0.1","jit_sudo_password":"x"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("non-ssh scan: %d", w.Code)
	}
	if w := post(`{"scan_type":"ssh","target":"t-jit","jit_sudo_password":"` + strings.Repeat("a", 300) + `"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("too long: %d", w.Code)
	}
	if len(exec.argv) != 0 {
		t.Fatalf("refused requests must not reach the host: %v", exec.argv)
	}
}

func TestNonInteractiveRunWithoutSudoSaysItNeedsAPassword(t *testing.T) {
	post, _, _, _, done, _ := jitScanFixture(t, "x", nil)
	if w := post(`{"scan_type":"ssh","target":"t-jit"}`); w.Code != http.StatusCreated {
		t.Fatalf("%d", w.Code)
	}
	<-done
	targets, creds := winrmTestStores(t)
	_, _ = creds.Create(context.Background(), "c", "k", CredentialTypeSSHKey, "", sshPayloadWithPrivilege(t, nil))
	_, _ = targets.Create(context.Background(), ManagedTarget{ID: "t", Name: "t", Host: "192.0.2.1", DiscoveryMode: "network", InstallMode: "ssh", RenewalMethod: "manual", CredentialRef: "c"})
	run := newSSHTargetScanner(targets, creds, &sshRecordingAudit{}, func(context.Context, agentinstall.SSHTarget) (agentinstall.Executor, func() error, error) {
		return newPrivFake(t, "x"), func() error { return nil }, nil
	})
	res := run(context.Background(), "t")
	found := false
	for _, f := range res.Endpoints[0].Findings {
		if strings.HasPrefix(f, "INSUFFICIENT_PRIVILEGE:") && strings.Contains(f, "run the scan once with a sudo password") {
			found = true
		}
	}
	if !found {
		t.Fatalf("findings: %v", res.Endpoints[0].Findings)
	}
}
