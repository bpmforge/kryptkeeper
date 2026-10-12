// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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
