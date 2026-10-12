// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWithRequestIDUsesIncomingHeaderWhenValid(t *testing.T) {
	const inbound = "req-client-123"

	h := withRequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := requestIDFromContext(r.Context()); got != inbound {
			t.Fatalf("expected request id in context %q, got %q", inbound, got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set(requestIDHeader, inbound)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if got := rec.Header().Get(requestIDHeader); got != inbound {
		t.Fatalf("expected response request id %q, got %q", inbound, got)
	}
}

func TestWithRequestIDGeneratesHeaderWhenMissing(t *testing.T) {
	h := withRequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := requestIDFromContext(r.Context()); got == "" {
			t.Fatal("expected generated request id in context")
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if got := rec.Header().Get(requestIDHeader); got == "" {
		t.Fatal("expected generated request id response header")
	}
}
