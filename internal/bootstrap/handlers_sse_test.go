// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// testSSEConfig gives every non-timing-focused test generous connection
// bounds so only the behavior under test can end the stream.
func testSSEConfig() sseConfig {
	return sseConfig{
		heartbeatInterval: 10 * time.Second,
		idleTimeout:       10 * time.Second,
		maxLifetime:       10 * time.Second,
	}
}

// sseClient is a minimal SSE reader for tests: it keeps a background
// goroutine draining the response body into a channel of trimmed lines so
// tests can select with a timeout instead of blocking forever on a stream
// that (by design, per acceptance #8) may never send anything.
type sseClient struct {
	cancel context.CancelFunc
	body   io.Closer
	lines  chan string
}

func connectSSE(t *testing.T, baseURL, token, tenant string) *sseClient {
	t.Helper()
	resp, cancel := trySSE(t, baseURL, token, tenant)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		cancel()
		t.Fatalf("expected 200 connecting SSE stream, got %d: %s", resp.StatusCode, body)
	}
	c := &sseClient{cancel: cancel, body: resp.Body, lines: make(chan string, 64)}
	go func() {
		r := bufio.NewReader(resp.Body)
		for {
			line, err := r.ReadString('\n')
			if trimmed := strings.TrimRight(line, "\n"); trimmed != "" {
				c.lines <- trimmed
			}
			if err != nil {
				close(c.lines)
				return
			}
		}
	}()
	return c
}

// trySSE issues the GET without asserting on the response, so callers can
// exercise non-200 outcomes (e.g. the 429 cap response).
func trySSE(t *testing.T, baseURL, token, tenant string) (*http.Response, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/v1/events", nil)
	if err != nil {
		cancel()
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if tenant != "" {
		req.Header.Set("X-Tenant", tenant)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		t.Fatalf("connect: %v", err)
	}
	return resp, cancel
}

func (c *sseClient) close() {
	c.cancel()
	c.body.Close()
}

// nextEvent returns the next `data:` line decoded as an Event, skipping
// heartbeat comment lines, or ok=false if none arrives within timeout.
func (c *sseClient) nextEvent(t *testing.T, timeout time.Duration) (Event, bool) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case line, open := <-c.lines:
			if !open {
				return Event{}, false
			}
			if !strings.HasPrefix(line, "data: ") {
				continue
			}
			var evt Event
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &evt); err != nil {
				t.Fatalf("decode event line %q: %v", line, err)
			}
			return evt, true
		case <-deadline:
			return Event{}, false
		}
	}
}

func (c *sseClient) expectNoEvent(t *testing.T, timeout time.Duration) {
	t.Helper()
	if evt, ok := c.nextEvent(t, timeout); ok {
		t.Fatalf("expected no event to be delivered, got %+v", evt)
	}
}

func (c *sseClient) nextRawLine(t *testing.T, timeout time.Duration) (string, bool) {
	t.Helper()
	select {
	case line, open := <-c.lines:
		return line, open
	case <-time.After(timeout):
		return "", false
	}
}

func newSSETestAPIKey(t *testing.T, auth *Authenticator, principalID, role, tenant string) string {
	t.Helper()
	_, token, err := auth.CreateAPIKey(principalID, principalID, role, nil, "", tenant, time.Now())
	if err != nil {
		t.Fatalf("create api key for %s: %v", principalID, err)
	}
	return token
}

// TestSSE_EventEnvelopeShapeOnWire is the acceptance #2 regression: the
// envelope on the wire must be exactly {op_id, kind, status, progress,
// message, ts}, progress an integer, ts RFC3339.
func TestSSE_EventEnvelopeShapeOnWire(t *testing.T) {
	auth := newRateLimitTestAuth(t)
	token := newSSETestAPIKey(t, auth, "watcher", "pki-operator", "")

	bus := NewEventBus(3)
	mux := http.NewServeMux()
	registerSSEHandlers(mux, auth, bus, stubAuditProvider{}, testSSEConfig())
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := connectSSE(t, srv.URL, token, "")
	defer c.close()

	progress := 55
	want := Event{OpID: "scan-9", Kind: EventKindScan, Status: "running", Progress: &progress, Message: "halfway", Ts: "2026-07-29T12:00:00Z"}
	bus.Publish(DefaultTenant, want)

	got, ok := c.nextEvent(t, 2*time.Second)
	if !ok {
		t.Fatal("expected an event, got none")
	}
	if got.OpID != want.OpID || got.Kind != want.Kind || got.Status != want.Status || got.Message != want.Message || got.Ts != want.Ts {
		t.Fatalf("envelope mismatch: got %+v want %+v", got, want)
	}
	if got.Progress == nil || *got.Progress != 55 {
		t.Fatalf("expected progress 55, got %+v", got.Progress)
	}
	if _, err := time.Parse(time.RFC3339, got.Ts); err != nil {
		t.Fatalf("ts is not RFC3339: %v", err)
	}
}

// TestSSE_NullProgressWhenUnreportable proves a nil Progress renders as JSON
// null on the wire (acceptance #2), not an omitted field or a fabricated 0.
func TestSSE_NullProgressWhenUnreportable(t *testing.T) {
	auth := newRateLimitTestAuth(t)
	token := newSSETestAPIKey(t, auth, "watcher", "pki-operator", "")

	bus := NewEventBus(3)
	mux := http.NewServeMux()
	registerSSEHandlers(mux, auth, bus, stubAuditProvider{}, testSSEConfig())
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := connectSSE(t, srv.URL, token, "")
	defer c.close()

	bus.Publish(DefaultTenant, Event{OpID: "scan-9", Kind: EventKindScan, Status: "queued", Ts: "2026-07-29T12:00:00Z"})

	line, ok := c.nextRawLine(t, 2*time.Second)
	if !ok || !strings.HasPrefix(line, "id: ") {
		t.Fatalf("expected an id line first, got %q ok=%v", line, ok)
	}
	line, ok = c.nextRawLine(t, 2*time.Second)
	if !ok {
		t.Fatal("expected an event line, got none")
	}
	if !strings.Contains(line, `"progress":null`) {
		t.Fatalf("expected progress:null on the wire, got %q", line)
	}
}

// TestSSE_TenantIsolation is the acceptance #4 regression: a non-super-admin
// principal in one tenant must never receive another tenant's events, in
// either direction.
func TestSSE_TenantIsolation(t *testing.T) {
	t.Setenv("MULTI_TENANCY", "on")
	auth := newRateLimitTestAuth(t)
	acmeToken := newSSETestAPIKey(t, auth, "acme-watcher", "pki-operator", "acme")
	globexToken := newSSETestAPIKey(t, auth, "globex-watcher", "pki-operator", "globex")

	bus := NewEventBus(3)
	mux := http.NewServeMux()
	registerSSEHandlers(mux, auth, bus, stubAuditProvider{}, testSSEConfig())
	srv := httptest.NewServer(mux)
	defer srv.Close()

	acme := connectSSE(t, srv.URL, acmeToken, "acme")
	defer acme.close()
	globex := connectSSE(t, srv.URL, globexToken, "globex")
	defer globex.close()

	bus.Publish("acme", Event{OpID: "scan-acme", Kind: EventKindScan, Status: "running", Ts: "2026-07-29T12:00:00Z"})
	if evt, ok := acme.nextEvent(t, 2*time.Second); !ok || evt.OpID != "scan-acme" {
		t.Fatalf("acme principal should receive its own tenant's event, got ok=%v evt=%+v", ok, evt)
	}
	globex.expectNoEvent(t, 300*time.Millisecond)

	bus.Publish("globex", Event{OpID: "scan-globex", Kind: EventKindScan, Status: "running", Ts: "2026-07-29T12:00:01Z"})
	if evt, ok := globex.nextEvent(t, 2*time.Second); !ok || evt.OpID != "scan-globex" {
		t.Fatalf("globex principal should receive its own tenant's event, got ok=%v evt=%+v", ok, evt)
	}
	acme.expectNoEvent(t, 300*time.Millisecond)
}

// TestSSE_ConcurrencyCapReturns429WithoutDroppingExistingStreams is the
// acceptance #5 regression.
func TestSSE_ConcurrencyCapReturns429WithoutDroppingExistingStreams(t *testing.T) {
	auth := newRateLimitTestAuth(t)
	token := newSSETestAPIKey(t, auth, "watcher", "pki-operator", "")

	bus := NewEventBus(2)
	mux := http.NewServeMux()
	registerSSEHandlers(mux, auth, bus, stubAuditProvider{}, testSSEConfig())
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c1 := connectSSE(t, srv.URL, token, "")
	defer c1.close()
	c2 := connectSSE(t, srv.URL, token, "")
	defer c2.close()

	resp3, cancel3 := trySSE(t, srv.URL, token, "")
	defer cancel3()
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 once the per-principal cap is reached, got %d", resp3.StatusCode)
	}

	// The rejected 3rd attempt must not have evicted either existing stream.
	bus.Publish(DefaultTenant, Event{OpID: "op-1", Kind: EventKindScan, Status: "running", Ts: "2026-07-29T12:00:00Z"})
	if evt, ok := c1.nextEvent(t, 2*time.Second); !ok || evt.OpID != "op-1" {
		t.Fatalf("stream 1 should still be alive after the cap rejection, got ok=%v evt=%+v", ok, evt)
	}
	if evt, ok := c2.nextEvent(t, 2*time.Second); !ok || evt.OpID != "op-1" {
		t.Fatalf("stream 2 should still be alive after the cap rejection, got ok=%v evt=%+v", ok, evt)
	}
}

// TestSSE_HeartbeatSentOnIdleConnection is the acceptance #6 regression.
func TestSSE_HeartbeatSentOnIdleConnection(t *testing.T) {
	auth := newRateLimitTestAuth(t)
	token := newSSETestAPIKey(t, auth, "watcher", "pki-operator", "")

	bus := NewEventBus(3)
	mux := http.NewServeMux()
	cfg := sseConfig{heartbeatInterval: 20 * time.Millisecond, idleTimeout: 5 * time.Second, maxLifetime: 5 * time.Second}
	registerSSEHandlers(mux, auth, bus, stubAuditProvider{}, cfg)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := connectSSE(t, srv.URL, token, "")
	defer c.close()

	line, ok := c.nextRawLine(t, time.Second)
	if !ok {
		t.Fatal("expected a heartbeat line on an idle connection, got none")
	}
	if !strings.HasPrefix(line, ":") {
		t.Fatalf("expected an SSE comment line (heartbeat), got %q", line)
	}
}

// TestSSE_IdleTimeoutClosesStreamDespiteHeartbeats proves idle timeout is a
// distinct bound from the heartbeat, not reset by it: a stream with no real
// events must close close to idleTimeout even though heartbeats keep
// arriving on the wire the whole time. maxLifetime is set far larger than
// idleTimeout specifically so the assertion on elapsed time can tell the two
// bounds apart -- an earlier draft of this test only asserted the stream
// closed "eventually" (within an unbounded drain of c.lines), which passed
// identically whether idle fired at 150ms or heartbeat kept resetting it and
// only maxLifetime (a much larger bound) eventually closed the stream --
// i.e. it could not actually distinguish the bug from the fix. Verified
// red/green: temporarily restored resetTimer(idle, ...) in the heartbeat
// branch of serveEventStream (handlers_sse.go) and confirmed this test's
// elapsed-time assertion failed (stream ran until maxLifetime instead of
// idleTimeout), then reverted and confirmed it passes again.
func TestSSE_IdleTimeoutClosesStreamDespiteHeartbeats(t *testing.T) {
	auth := newRateLimitTestAuth(t)
	token := newSSETestAPIKey(t, auth, "watcher", "pki-operator", "")

	bus := NewEventBus(3)
	mux := http.NewServeMux()
	// Margins widened from an earlier draft (150ms/2s) after a one-off flake
	// under system load: idleTimeout/maxLifetime stay two orders of magnitude
	// apart (so the elapsed-time assertion below still tells them apart), but
	// with more absolute slack for scheduler jitter on a loaded CI box.
	cfg := sseConfig{heartbeatInterval: 25 * time.Millisecond, idleTimeout: 300 * time.Millisecond, maxLifetime: 5 * time.Second}
	registerSSEHandlers(mux, auth, bus, stubAuditProvider{}, cfg)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	start := time.Now()
	c := connectSSE(t, srv.URL, token, "")
	defer c.close()

	deadline := time.After(3 * time.Second)
	for {
		select {
		case _, open := <-c.lines:
			if !open {
				elapsed := time.Since(start)
				if elapsed > 1500*time.Millisecond {
					t.Fatalf("stream took %v to close -- idleTimeout (%v) never fired; only a much larger bound (maxLifetime=%v) explains this delay", elapsed, cfg.idleTimeout, cfg.maxLifetime)
				}
				if elapsed < cfg.idleTimeout {
					t.Fatalf("stream closed after %v, before idleTimeout (%v) could have fired", elapsed, cfg.idleTimeout)
				}
				return
			}
			// Still draining heartbeat lines; keep waiting for close.
		case <-deadline:
			t.Fatal("expected the stream to close on idle timeout despite heartbeats, but it stayed open")
		}
	}
}

func TestSSE_UnauthorizedWithoutValidToken(t *testing.T) {
	auth := newRateLimitTestAuth(t)
	bus := NewEventBus(3)
	mux := http.NewServeMux()
	registerSSEHandlers(mux, auth, bus, stubAuditProvider{}, testSSEConfig())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestSSE_ForbiddenForRoleWithoutReadAccess(t *testing.T) {
	auth := newRateLimitTestAuth(t)
	token := newSSETestAPIKey(t, auth, "viewer", "pki-viewer", "")
	bus := NewEventBus(3)
	mux := http.NewServeMux()
	registerSSEHandlers(mux, auth, bus, stubAuditProvider{}, testSSEConfig())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestSSE_MethodNotAllowedForNonGET(t *testing.T) {
	auth := newRateLimitTestAuth(t)
	token := newSSETestAPIKey(t, auth, "watcher", "pki-operator", "")
	bus := NewEventBus(3)
	mux := http.NewServeMux()
	registerSSEHandlers(mux, auth, bus, stubAuditProvider{}, testSSEConfig())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/events", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

// sseAuditRecorder records audit actions so tests can assert on the
// events.stream.* names.
type sseAuditRecorder struct {
	mu      sync.Mutex
	entries []AuditEntry
}

func (a *sseAuditRecorder) ListEntries(context.Context, AuditListQuery) (AuditListResult, error) {
	return AuditListResult{Entries: []AuditEntry{}, Limit: 25}, nil
}

func (a *sseAuditRecorder) AppendEntry(_ context.Context, e AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, e)
	return nil
}

func (a *sseAuditRecorder) count(action string, outcome AuditOutcome) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, e := range a.entries {
		if e.Action == action && e.Outcome == outcome {
			n++
		}
	}
	return n
}

// countEventually polls count for up to 2 s: a stream's open audit is written
// by the handler goroutine, which can lag the client seeing headers on a
// loaded host.
func (a *sseAuditRecorder) countEventually(action string, outcome AuditOutcome, want int) int {
	deadline := time.Now().Add(2 * time.Second)
	for {
		n := a.count(action, outcome)
		if n >= want || time.Now().After(deadline) {
			return n
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// expectStatuses reads len(want) events for opID and asserts their statuses
// in order, skipping other ops.
func (c *sseClient) expectStatuses(t *testing.T, kind, opID string, want ...string) {
	t.Helper()
	for i, w := range want {
		evt, ok := c.nextEvent(t, 3*time.Second)
		if !ok {
			t.Fatalf("event %d (%s): none delivered", i, w)
		}
		if evt.Kind != kind || evt.OpID != opID || evt.Status != w {
			t.Fatalf("event %d: got kind=%s op=%s status=%s, want kind=%s op=%s status=%s", i, evt.Kind, evt.OpID, evt.Status, kind, opID, w)
		}
	}
}

type stubRenewalRunner struct {
	result RenewalExecuteResult
	err    error
}

func (s stubRenewalRunner) ExecuteRenewal(context.Context, string, ManagedTarget, RenewalInstallProfile) (RenewalExecuteResult, error) {
	return s.result, s.err
}

// renewSSEHarness mounts the SSE stream and the renewal handler on one mux
// sharing one Authenticator and bus.
type renewSSEHarness struct {
	srv         *httptest.Server
	auth        *Authenticator
	bus         *EventBus
	audit       *sseAuditRecorder
	fingerprint string
	targetID    string
	caID        string
}

func newRenewSSEHarness(t *testing.T, runner renewalRunner, maxStreams int) *renewSSEHarness {
	t.Helper()
	t.Cleanup(func() { setActiveEventBus(nil) })
	_, auth, provider, targetStore, credStore, caID := newRenewalExecuteTestMuxAuth(t)
	ctx := context.Background()
	issued, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID: caID, CSRPEM: generateTestCSRPEM(t, "sse.example.com", "sse.example.com"),
		TemplateID: "file-backed-default", TeamID: "team-sse",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	target, err := targetStore.Create(ctx, ManagedTarget{
		ID: "tgt-sse", Name: "sse-target", Tenant: "acme", Host: "127.0.0.1",
		DiscoveryMode: "none", InstallMode: "ssh", RenewalMethod: "manual", CredentialRef: "cred-sse",
	})
	if err != nil {
		t.Fatalf("target: %v", err)
	}
	audit := &sseAuditRecorder{}
	bus := NewEventBus(maxStreams)
	mux := http.NewServeMux()
	registerSSEHandlers(mux, auth, bus, audit, testSSEConfig())
	registerRenewalExecuteHandlerWithRunner(mux, auth, provider, targetStore, credStore, audit, runner, time.Minute)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &renewSSEHarness{srv: srv, auth: auth, bus: bus, audit: audit, fingerprint: issued.CertificateItem.FingerprintSHA256, targetID: target.ID, caID: caID}
}

func (h *renewSSEHarness) renew(t *testing.T, token, tenant string) int {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"fingerprint": h.fingerprint, "target_id": h.targetID})
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/api/v1/renewal/execute", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	if tenant != "" {
		req.Header.Set("X-Tenant", tenant)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func TestSSE_RenewProducerLifecycle(t *testing.T) {
	h := newRenewSSEHarness(t, stubRenewalRunner{result: RenewalExecuteResult{InstallOutcome: "installed_verified"}}, 5)
	token := newSSETestAPIKey(t, h.auth, "renewer", "pki-admin", "")
	c := connectSSE(t, h.srv.URL, token, "")
	defer c.close()

	if code := h.renew(t, token, ""); code != http.StatusOK {
		t.Fatalf("renew: %d", code)
	}
	c.expectStatuses(t, EventKindRenew, h.fingerprint, "queued", "running", "completed")

	failing := newRenewSSEHarness(t, stubRenewalRunner{err: errors.New("acme account key=SECRET rejected")}, 5)
	ftoken := newSSETestAPIKey(t, failing.auth, "renewer", "pki-admin", "")
	fc := connectSSE(t, failing.srv.URL, ftoken, "")
	defer fc.close()
	if code := failing.renew(t, ftoken, ""); code != http.StatusServiceUnavailable {
		t.Fatalf("failing renew: %d", code)
	}
	fc.expectStatuses(t, EventKindRenew, failing.fingerprint, "queued", "running")
	evt, ok := fc.nextEvent(t, 3*time.Second)
	if !ok || evt.Status != "failed" {
		t.Fatalf("expected failed, got ok=%v %+v", ok, evt)
	}
	if strings.Contains(evt.Message, "SECRET") {
		t.Fatalf("failure message leaked the executor error: %q", evt.Message)
	}
}

func TestSSE_OperationSucceedsWithZeroSubscribers(t *testing.T) {
	h := newRenewSSEHarness(t, stubRenewalRunner{result: RenewalExecuteResult{InstallOutcome: "installed_verified"}}, 5)
	token := newSSETestAPIKey(t, h.auth, "renewer", "pki-admin", "")
	if code := h.renew(t, token, ""); code != http.StatusOK {
		t.Fatalf("renew with no subscribers: %d", code)
	}
}

// TestSSE_CrossTenantNotDelivered: an acme-initiated renewal must reach acme
// subscribers only.
func TestSSE_CrossTenantNotDelivered(t *testing.T) {
	t.Setenv("MULTI_TENANCY", "on")
	// Tenant gates fail closed without a store (D-202), so give the test its
	// own store with the harness CA mapped to acme.
	prevStore := activeTenantStore
	t.Cleanup(func() { setActiveTenantStore(prevStore) })
	h := newRenewSSEHarness(t, stubRenewalRunner{result: RenewalExecuteResult{InstallOutcome: "installed_verified"}}, 5)
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	ts := NewTenantStoreFromEnv()
	if ts == nil {
		t.Fatal("tenant store unavailable")
	}
	for _, id := range []string{"acme", "globex"} {
		if _, err := ts.CreateTenant(context.Background(), id, id); err != nil {
			t.Fatal(err)
		}
	}
	if err := ts.SetCATenant(context.Background(), h.caID, "acme"); err != nil {
		t.Fatal(err)
	}
	setActiveTenantStore(ts)
	acmeToken := newSSETestAPIKey(t, h.auth, "acme-op", "pki-admin", "acme")
	globexToken := newSSETestAPIKey(t, h.auth, "globex-op", "pki-operator", "globex")
	acme := connectSSE(t, h.srv.URL, acmeToken, "acme")
	defer acme.close()
	globex := connectSSE(t, h.srv.URL, globexToken, "globex")
	defer globex.close()

	if code := h.renew(t, acmeToken, "acme"); code != http.StatusOK {
		t.Fatalf("acme renew: %d", code)
	}
	acme.expectStatuses(t, EventKindRenew, h.fingerprint, "queued", "running", "completed")
	globex.expectNoEvent(t, 400*time.Millisecond)

	// A globex principal cannot start a renewal on acme's target, so no
	// acme-visible event is produced either.
	globexAdmin := newSSETestAPIKey(t, h.auth, "globex-admin", "pki-admin", "globex")
	if code := h.renew(t, globexAdmin, "globex"); code != http.StatusForbidden {
		t.Fatalf("cross-tenant renew should be 403, got %d", code)
	}
	acme.expectNoEvent(t, 300*time.Millisecond)

	// Replay is tenant-filtered too: globex reconnecting with Last-Event-ID 0
	// must not be handed acme's buffered events.
	replayed := connectSSEWithLastID(t, h.srv.URL, globexToken, "globex", "0")
	defer replayed.close()
	replayed.expectNoEvent(t, 400*time.Millisecond)
}

func connectSSEWithLastID(t *testing.T, baseURL, token, tenant, lastID string) *sseClient {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/v1/events", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Last-Event-ID", lastID)
	if tenant != "" {
		req.Header.Set("X-Tenant", tenant)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		cancel()
		t.Fatalf("connect with Last-Event-ID: err=%v", err)
	}
	c := &sseClient{cancel: cancel, body: resp.Body, lines: make(chan string, 64)}
	go func() {
		r := bufio.NewReader(resp.Body)
		for {
			line, err := r.ReadString('\n')
			if trimmed := strings.TrimRight(line, "\n"); trimmed != "" {
				c.lines <- trimmed
			}
			if err != nil {
				close(c.lines)
				return
			}
		}
	}()
	return c
}

func TestSSE_SixthStreamReturns429(t *testing.T) {
	t.Cleanup(func() { setActiveEventBus(nil) })
	t.Setenv("APP_SSE_MAX_STREAMS_PER_PRINCIPAL", "")
	auth := newRateLimitTestAuth(t)
	token := newSSETestAPIKey(t, auth, "watcher", "pki-operator", "")
	audit := &sseAuditRecorder{}
	mux := http.NewServeMux()
	registerSSEHandlers(mux, auth, NewEventBus(sseMaxStreamsPerPrincipalFromEnv()), audit, testSSEConfig())
	srv := httptest.NewServer(mux)
	defer srv.Close()

	for i := 0; i < 5; i++ {
		c := connectSSE(t, srv.URL, token, "")
		defer c.close()
	}
	resp, cancel := trySSE(t, srv.URL, token, "")
	defer cancel()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on the 6th stream, got %d", resp.StatusCode)
	}
	if n := audit.countEventually("events.stream.reject", AuditOutcomeDenied, 1); n != 1 {
		t.Fatalf("expected 1 events.stream.reject audit row, got %d", n)
	}
	if n := audit.countEventually("events.stream.open", AuditOutcomeSuccess, 5); n != 5 {
		t.Fatalf("expected 5 events.stream.open audit rows, got %d", n)
	}
}

func TestSSE_StreamOpenAudited(t *testing.T) {
	t.Cleanup(func() { setActiveEventBus(nil) })
	auth := newRateLimitTestAuth(t)
	token := newSSETestAPIKey(t, auth, "watcher", "pki-operator", "")
	audit := &sseAuditRecorder{}
	bus := NewEventBus(5)
	mux := http.NewServeMux()
	registerSSEHandlers(mux, auth, bus, audit, testSSEConfig())
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := connectSSE(t, srv.URL, token, "")
	defer c.close()
	bus.Publish(DefaultTenant, Event{OpID: "x", Kind: EventKindScan, Status: "running", Ts: "2026-07-29T12:00:00Z"})
	if _, ok := c.nextEvent(t, 2*time.Second); !ok {
		t.Fatal("expected event")
	}
	if n := audit.count("events.stream.open", AuditOutcomeSuccess); n != 1 {
		t.Fatalf("expected exactly 1 events.stream.open row (never per message), got %d", n)
	}
}

func TestSSE_LastEventIDReplay(t *testing.T) {
	t.Cleanup(func() { setActiveEventBus(nil) })
	auth := newRateLimitTestAuth(t)
	token := newSSETestAPIKey(t, auth, "watcher", "pki-operator", "")
	bus := NewEventBus(5)
	mux := http.NewServeMux()
	registerSSEHandlers(mux, auth, bus, stubAuditProvider{}, testSSEConfig())
	srv := httptest.NewServer(mux)
	defer srv.Close()

	for _, id := range []string{"op-1", "op-2", "op-3"} {
		bus.Publish(DefaultTenant, Event{OpID: id, Kind: EventKindScan, Status: "running", Ts: "2026-07-29T12:00:00Z"})
	}
	c := connectSSEWithLastID(t, srv.URL, token, "", "1")
	defer c.close()
	for _, want := range []struct{ id, op string }{{"id: 2", "op-2"}, {"id: 3", "op-3"}} {
		line, ok := c.nextRawLine(t, 2*time.Second)
		if !ok || line != want.id {
			t.Fatalf("expected %q, got %q ok=%v", want.id, line, ok)
		}
		evt, ok := c.nextEvent(t, 2*time.Second)
		if !ok || evt.OpID != want.op {
			t.Fatalf("expected %s, got ok=%v %+v", want.op, ok, evt)
		}
	}
	c.expectNoEvent(t, 200*time.Millisecond)
}

func TestSSE_InstallProducerLifecycle(t *testing.T) {
	t.Cleanup(func() { setActiveEventBus(nil) })
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	mux, _ := newAgentMux(t)
	auth := newAgentTestAuth(t)
	registerSSEHandlers(mux, auth, NewEventBus(5), stubAuditProvider{}, testSSEConfig())
	srv := httptest.NewServer(mux)
	defer srv.Close()
	token := newSSETestAPIKey(t, auth, "watcher", "pki-operator", "")
	c := connectSSE(t, srv.URL, token, "")
	defer c.close()

	post := func(path, id, agentToken string, body any) {
		t.Helper()
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest(http.MethodPost, srv.URL+path, bytes.NewReader(b))
		req.Header.Set("X-Agent-ID", id)
		req.Header.Set("X-Agent-Token", agentToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("POST %s: err=%v", path, err)
		}
		resp.Body.Close()
	}
	get := func(path, id, agentToken string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		req.Header.Set("X-Agent-ID", id)
		req.Header.Set("X-Agent-Token", agentToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: err=%v", path, err)
		}
		resp.Body.Close()
	}

	runCycle := func(name, fp, outcome string, rolledBack bool, wantFinal string) {
		t.Helper()
		agentID, agentToken := registerTestAgent(t, mux, name, AgentTypeLinux)
		post("/api/v1/agent/inventory", agentID, agentToken, map[string]any{
			"certs":     []AgentDiscoveredCert{{Fingerprint: fp, Subject: "CN=shop.example.com", Source: "/etc/ssl/" + fp + ".crt", NotAfter: time.Now().Add(24 * time.Hour), AutoRenewable: true}},
			"endpoints": []AgentEndpoint{{ServerType: "nginx", CertPath: "/etc/ssl/" + fp + ".crt", KeyPath: "/etc/ssl/" + fp + ".key"}},
		})
		queued, ok := c.nextEvent(t, 3*time.Second)
		if !ok || queued.Kind != EventKindInstall || queued.Status != "queued" || queued.OpID == "" {
			t.Fatalf("expected install queued, got ok=%v %+v", ok, queued)
		}
		// Polling twice announces running once.
		get("/api/v1/agent/tasks", agentID, agentToken)
		get("/api/v1/agent/tasks", agentID, agentToken)
		c.expectStatuses(t, EventKindInstall, queued.OpID, "running")
		post("/api/v1/agent/renewal-result", agentID, agentToken, AgentRenewalResult{TaskID: queued.OpID, Fingerprint: fp, Outcome: outcome, RolledBack: rolledBack})
		c.expectStatuses(t, EventKindInstall, queued.OpID, wantFinal)
		c.expectNoEvent(t, 100*time.Millisecond)
	}
	runCycle("agent-ok", "fp-ok", "installed_verified", false, "completed")
	runCycle("agent-rb", "fp-rb", "rolled_back", true, "failed")
}

func TestSSE_MigrateProducerLifecycle(t *testing.T) {
	t.Cleanup(func() { setActiveEventBus(nil) })
	fx := newWaveExecuteTestFixture(t)
	registerSSEHandlers(fx.mux, fx.auth, NewEventBus(5), stubAuditProvider{}, testSSEConfig())
	srv := httptest.NewServer(fx.mux)
	defer srv.Close()
	watcher := waveExecuteToken(t, fx.auth, "watcher", "pki-operator")
	c := connectSSE(t, srv.URL, watcher, "")
	defer c.close()

	ctx := context.Background()
	caID := getFirstCAID(t, fx.engine)
	issued, err := fx.certs.IssueCertificate(ctx, CertificateIssueRequest{CAID: caID, TemplateID: "tpl-classical", CSRPEM: generateTestCSRPEM(t, "sse-migrate.example.com"), TeamID: "team-1"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	wave, err := fx.waveStore.CreateWave(ctx, MigrationWave{Name: "wave-sse"})
	if err != nil {
		t.Fatalf("create wave: %v", err)
	}
	for _, fp := range []string{issued.FingerprintSHA256, "does-not-exist"} {
		if err := fx.waveStore.AddMember(ctx, wave.ID, MigrationWaveMember{Fingerprint: fp}); err != nil {
			t.Fatalf("add member: %v", err)
		}
	}
	proposer := waveExecuteToken(t, fx.auth, "proposer", "pki-admin")
	action := proposeWaveExecute(t, fx, wave.ID, proposer)
	approver := waveExecuteToken(t, fx.auth, "approver", "pki-operator")
	rec := httptest.NewRecorder()
	fx.mux.ServeHTTP(rec, waveExecuteReq(http.MethodPost, "/api/v1/reports/pqc-waves/"+wave.ID+"/execute/"+action.ID+"/approve", approver, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}
	c.expectStatuses(t, EventKindMigrate, wave.ID, "running")
	evt, ok := c.nextEvent(t, 3*time.Second)
	if !ok || evt.OpID != wave.ID || evt.Status != "failed" || evt.Message != "1 of 2 members failed" {
		t.Fatalf("expected partial-failure event, got ok=%v %+v", ok, evt)
	}
}
