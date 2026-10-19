// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"kryptkeeper/internal/metrics"
)

func TestCertManagerOpsReadiness(t *testing.T) {
	h := metrics.OpsHandler(newOpsConfig("x"))
	code := func(p string) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		return rec.Code
	}
	ready.Store(false)
	if code("/healthz") != 200 || code("/readyz") != 503 {
		t.Fatal("not-running controller must be live but unready")
	}
	ready.Store(true)
	t.Cleanup(func() { ready.Store(false) })
	if code("/readyz") != 200 {
		t.Fatal("running controller must be ready")
	}
}
