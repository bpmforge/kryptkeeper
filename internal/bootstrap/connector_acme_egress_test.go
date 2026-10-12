// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// OWASP-A10-002: health detail is a fixed vocabulary, never a raw error.
func TestACMEHealthUsesFixedVocabulary(t *testing.T) {
	cases := []struct {
		name, url, want string
		loopback        bool
	}{
		{"metadata", "https://169.254.169.254/dir", "blocked destination", true},
		{"loopback not allowed", "https://127.0.0.1:1/dir", "blocked destination", false},
		{"plain http refused", "http://example.com/dir", "blocked destination", false},
		{"unreachable", "https://127.0.0.1:1/dir", "unreachable", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &acmeIssuerConnector{id: "c", cfg: acmeConnectorConfig{DirectoryURL: tc.url}, allowLoopbackForTest: tc.loopback}
			h := c.Health(context.Background())
			if h.Status != "degraded" || h.Detail != tc.want {
				t.Fatalf("got %+v, want degraded/%q", h, tc.want)
			}
		})
	}

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(502) }))
	defer bad.Close()
	c := &acmeIssuerConnector{id: "c", cfg: acmeConnectorConfig{DirectoryURL: bad.URL}, allowLoopbackForTest: true}
	if h := c.Health(context.Background()); h.Detail != "directory returned an error status" {
		t.Fatalf("got %+v", h)
	}
}
