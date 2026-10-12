// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

const (
	defaultSSEHeartbeatIntervalSeconds = 15
	// idleTimeout is NOT reset by the heartbeat (see serveEventStream) --
	// it bounds time since the last REAL event, not connection age. 300s
	// gives a scan/renewal with a quiet stretch between progress events
	// room to breathe while still bounding a truly unused stream.
	defaultSSEIdleTimeoutSeconds     = 300
	defaultSSEMaxLifetimeSeconds     = 1800 // 30 minutes
	defaultSSEMaxStreamsPerPrincipal = 3
)

// sseConfig bounds one SSE connection's lifecycle (W8-14 acceptance #5/#6).
type sseConfig struct {
	heartbeatInterval time.Duration
	idleTimeout       time.Duration
	maxLifetime       time.Duration
}

func sseConfigFromEnv() sseConfig {
	return sseConfig{
		heartbeatInterval: time.Duration(envClampedInt("APP_SSE_HEARTBEAT_INTERVAL_SECONDS", defaultSSEHeartbeatIntervalSeconds, 1, 300)) * time.Second,
		idleTimeout:       time.Duration(envClampedInt("APP_SSE_IDLE_TIMEOUT_SECONDS", defaultSSEIdleTimeoutSeconds, 5, 3600)) * time.Second,
		maxLifetime:       time.Duration(envClampedInt("APP_SSE_MAX_LIFETIME_SECONDS", defaultSSEMaxLifetimeSeconds, 30, 24*3600)) * time.Second,
	}
}

func sseMaxStreamsPerPrincipalFromEnv() int {
	return envClampedInt("APP_SSE_MAX_STREAMS_PER_PRINCIPAL", defaultSSEMaxStreamsPerPrincipal, 1, 32)
}

// registerSSEHandlers wires GET /api/v1/events, the single tenant-scoped
// operation-status stream (W8-14). One stream carries every operation kind;
// clients filter client-side on each event's `kind` field rather than
// opening a stream per kind (acceptance #1).
func registerSSEHandlers(mux *http.ServeMux, auth *Authenticator, bus *EventBus, auditProvider AuditProvider, cfg sseConfig) {
	mux.HandleFunc("/api/v1/events", func(w http.ResponseWriter, r *http.Request) {
		// Auth is checked before the method, matching handlers_discovery.go
		// and response.go's getOnly doc comment: an authenticated route must
		// never disclose which methods it supports to an unauthenticated
		// caller (S-31/S-32).
		principal, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "events.stream", "events", "stream", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		if !canReadOperationalSummaries(principal) {
			emitAuditEvent(r, auditProvider, principal.ID, "events.stream", "events", "stream", AuditOutcomeDenied)
			writeForbidden(w, "forbidden")
			return
		}

		flusher, ok := w.(http.Flusher)
		if !ok {
			emitAuditEvent(r, auditProvider, principal.ID, "events.stream", "events", "stream", AuditOutcomeFailure)
			writeServiceUnavailable(w, "streaming unsupported")
			return
		}

		// Cap concurrent streams per principal (acceptance #5): rejecting
		// here, before any header is written, means a 429 never touches any
		// of the principal's existing streams.
		sub, ok := bus.Subscribe(principal.ID)
		if !ok {
			emitAuditEvent(r, auditProvider, principal.ID, "events.stream", "events", "stream", AuditOutcomeDenied)
			writeTooManyRequests(w, "too many concurrent event streams for this principal")
			return
		}
		defer bus.Unsubscribe(principal.ID, sub)

		// server.go's http.Server sets ReadTimeout/WriteTimeout to 15s for
		// every ordinary request; those deadlines are NOT reset by writes
		// after the initial request read, so an SSE stream left under them
		// would be killed by the server itself around 15s in, well inside
		// the heartbeat interval acceptance #6 depends on. Disabling both
		// per-connection here hands lifecycle bounding entirely to this
		// handler's own idle/lifetime timers below -- server.go is outside
		// this ticket's write_scope, so a per-connection override here is
		// the only seam available. A ResponseWriter that doesn't support
		// this (e.g. httptest.ResponseRecorder in tests) returns
		// ErrNotSupported, which is safe to ignore: those callers have no
		// deadline to begin with.
		rc := http.NewResponseController(w)
		_ = rc.SetWriteDeadline(time.Time{}) // clearing deadlines; failure only shortens the stream
		_ = rc.SetReadDeadline(time.Time{})  // clearing deadlines; failure only shortens the stream

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		// nginx buffers proxied responses by default (S-03 put one in front
		// of this API); without this header, heartbeats and events can sit
		// in nginx's buffer instead of reaching the client, silently
		// defeating both the heartbeat and the stream itself.
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(http.StatusOK)
		flusher.Flush()

		emitAuditEvent(r, auditProvider, principal.ID, "events.stream", "events", "stream", AuditOutcomeSuccess)

		serveEventStream(r, w, flusher, principal, sub, cfg)
	})
}

// serveEventStream runs one connection's read/heartbeat/timeout loop until
// the client disconnects, the connection's bounds are exceeded, or the
// subscription is torn down. Every branch that writes to w is followed by a
// Flush, and any write error ends the loop -- a stalled or gone client must
// never wedge this goroutine open.
func serveEventStream(r *http.Request, w http.ResponseWriter, flusher http.Flusher, principal AuthPrincipal, sub *eventSubscriber, cfg sseConfig) {
	ctx := r.Context()

	lifetime := time.NewTimer(cfg.maxLifetime)
	defer lifetime.Stop()
	idle := time.NewTimer(cfg.idleTimeout)
	defer idle.Stop()
	heartbeat := time.NewTicker(cfg.heartbeatInterval)
	defer heartbeat.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-lifetime.C:
			return
		case <-idle.C:
			return
		case <-heartbeat.C:
			// SSE comment line: ignored as data by any conforming client,
			// but it is bytes on the wire, which is what keeps an
			// idle-but-healthy stream from being reaped by a proxy or load
			// balancer sitting in front of it (acceptance #6). Deliberately
			// does NOT reset idle: idle bounds how long this stream may go
			// without a REAL event, freeing its cap slot for a mostly-unused
			// connection, which is a distinct control from the heartbeat
			// that keeps that same idle-but-healthy stream from being
			// reaped by a proxy. If heartbeat reset idle too, idle could
			// never fire while the heartbeat ticker keeps running (it
			// always does), making the bound acceptance #5 requires dead.
			if _, err := io.WriteString(w, ": heartbeat\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case te, open := <-sub.ch:
			if !open {
				return
			}
			// Tenant scoping goes through the same resolvePrincipalTenancy
			// output every other tenant-filtered read uses (acceptance #4)
			// -- tenantVisible is handlers_tenants.go's existing helper, not
			// a new isolation path.
			if !tenantVisible(principal, te.tenant) {
				continue
			}
			payload, err := json.Marshal(te.event)
			if err != nil {
				log.Printf("sse: failed to encode event op_id=%s: %v", te.event.OpID, err)
				continue
			}
			if _, err := fmt.Fprintf(w, "data: %s\n\n", payload); err != nil {
				return
			}
			flusher.Flush()
			resetTimer(idle, cfg.idleTimeout)
		}
	}
}

// resetTimer safely reschedules t to fire after d, draining an already-fired
// but unread tick first per time.Timer.Reset's documented caveat -- skipping
// this can leave a stale tick in the channel that fires the loop's idle
// branch immediately on the next select.
func resetTimer(t *time.Timer, d time.Duration) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	t.Reset(d)
}
