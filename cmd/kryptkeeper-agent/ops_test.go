// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"kryptkeeper/internal/metrics"
)

func probe(t *testing.T, h http.Handler, path string) int {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Code
}

func TestAgentOpsReadiness(t *testing.T) {
	base := time.Unix(1_000_000, 0)
	clock := base
	lastHeartbeatOK.Store(0)
	t.Cleanup(func() { lastHeartbeatOK.Store(0) })
	h := metrics.OpsHandler(newOpsConfig("x", 60*time.Second, func() time.Time { return clock }))

	if got := probe(t, h, "/healthz"); got != 200 {
		t.Fatalf("healthz before heartbeat = %d", got)
	}
	if got := probe(t, h, "/readyz"); got != 503 {
		t.Fatalf("readyz before first heartbeat = %d, want 503", got)
	}
	lastHeartbeatOK.Store(base.Unix())
	if got := probe(t, h, "/readyz"); got != 200 {
		t.Fatalf("readyz after heartbeat = %d", got)
	}
	clock = base.Add(3*60*time.Second + time.Minute + time.Second)
	if got := probe(t, h, "/readyz"); got != 503 {
		t.Fatalf("readyz when stale = %d, want 503", got)
	}
}
