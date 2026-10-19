// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"kryptkeeper/internal/mcpserver"
	"kryptkeeper/internal/metrics"
)

func readyzCode(h http.Handler) int {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	return rec.Code
}

func TestMCPOpsReadiness(t *testing.T) {
	var canApprove atomic.Bool
	var calls atomic.Int32
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if canApprove.Load() {
			_, _ = w.Write([]byte(`{"role":"pki-admin","can_approve_actions":true}`))
			return
		}
		_, _ = w.Write([]byte(`{"role":"mcp-agent","can_approve_actions":false}`))
	}))
	client := mcpserver.NewHubClient(hub.URL, "tok")
	clock := time.Unix(1000, 0)
	h := metrics.OpsHandler(newOpsConfig("x", client, func() time.Time { return clock }))

	if got := readyzCode(h); got != 200 {
		t.Fatalf("mcp-agent role = %d, want 200", got)
	}
	readyzCode(h)
	if calls.Load() != 1 {
		t.Fatalf("hub called %d times within TTL, want 1 (cache)", calls.Load())
	}

	clock = clock.Add(opsRoleCacheTTL + time.Second)
	canApprove.Store(true)
	if got := readyzCode(h); got != 503 {
		t.Fatalf("approver role = %d, want 503", got)
	}

	clock = clock.Add(opsRoleCacheTTL + time.Second)
	canApprove.Store(false)
	hub.Close()
	if got := readyzCode(h); got != 503 {
		t.Fatalf("hub down = %d, want 503", got)
	}
}
