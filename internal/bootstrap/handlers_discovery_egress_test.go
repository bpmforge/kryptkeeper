// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// OWASP-A10-003 / A04-005: link-local targets and oversized CIDRs are
// rejected with 400 before a job is queued.
func TestDiscoveryScanCreate_RejectsDeniedAndOversizedTargets(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("KRYPTKEEPER_DISCOVERY_DENY_CIDRS", "10.99.0.0/16")
	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	registerDiscoveryHandlers(mux, auth, discoveryEventTestProvider{
		createResult: DiscoveryScanCreateResult{ID: "scan-1", Status: "queued", ScanType: "full", Target: "x", QueuedAt: "2026-07-29T00:00:00Z"},
	}, NewEventBus(3), stubAuditProvider{})

	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/discovery/scans", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer test-token")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}
	for _, tc := range []struct {
		name, body string
		want       int
	}{
		{"metadata ip", `{"scan_type":"full","target":"169.254.169.254"}`, 400},
		{"metadata ip:port", `{"scan_type":"full","target":"169.254.169.254:80"}`, 400},
		{"link-local cidr", `{"scan_type":"fast","target":"169.254.0.0/16"}`, 400},
		{"operator deny", `{"scan_type":"full","target":"10.99.1.0/24"}`, 400},
		{"huge cidr", `{"scan_type":"fast","target":"10.0.0.0/8"}`, 400},
		{"ipv6 huge", `{"scan_type":"fast","target":"2001:db8::/32"}`, 400},
		{"ok /24", `{"scan_type":"fast","target":"10.0.0.0/28"}`, 201},
		{"ok pinned host", `{"scan_type":"full","target":"10.0.0.5:8443"}`, 201},
	} {
		if rec := post(tc.body); rec.Code != tc.want {
			t.Errorf("%s: got %d want %d (%s)", tc.name, rec.Code, tc.want, rec.Body.String())
		}
	}
}
